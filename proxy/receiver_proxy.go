package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flashbots/go-utils/rpcclient"
	"github.com/flashbots/go-utils/signature"
	"github.com/google/uuid"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/time/rate"
)

var (
	requestsRLUSize = 4096
	requestsRLUTTL  = time.Second * 12

	peerUpdateTime = time.Second * 30

	replacementNonceSize = 4096
	replacementNonceTTL  = time.Second * 5 * 12

	ReceiverProxyWorkerQueueSize = 10000
)

type replacementNonceKey struct {
	uuid   uuid.UUID
	signer common.Address
}

type ReceiverProxy struct {
	ReceiverProxyConstantConfig

	OrderflowSigner *signature.Signer
	ClientCAs       *x509.CertPool
	PublicCertPEM   []byte
	Certificate     tls.Certificate

	localBuilder rpcclient.RPCClient

	UserHandler   http.Handler
	SystemHandler http.Handler
	CertHandler   http.Handler // this endpoint just returns generated certificate

	updatePeers chan []ConfighubBuilder
	shareQueue  chan *ParsedRequest

	archiveQueue      chan *ParsedRequest
	archiveFlushQueue chan struct{}

	peersMu          sync.RWMutex
	lastFetchedPeers []ConfighubBuilder

	requestUniqueKeysRLU *expirable.LRU[uuid.UUID, struct{}]

	replacementNonceRLU *expirable.LRU[replacementNonceKey, int]

	peerUpdaterClose chan struct{}

	userAPIRateLimiter *rate.Limiter
}

type ReceiverProxyConstantConfig struct {
	Log *slog.Logger
	// Name is optional field and it used to distringuish multiple proxies when running in the same process in tests
	Name                   string
	FlashbotsSignerAddress common.Address
}

type ReceiverProxyConfig struct {
	ReceiverProxyConstantConfig

	CertValidDuration time.Duration
	CertHosts         []string
	CACertPath        string
	CertPath          string
	CertKeyPath       string

	ArchiveEndpoint      string
	ArchiveConnections   int
	LocalBuilderEndpoint string

	// EthRPC should support eth_blockNumber API
	EthRPC string

	MaxRequestBodySizeBytes int64

	ConnectionsPerPeer int
	MaxUserRPS         int
}

func NewReceiverProxy(config ReceiverProxyConfig) (*ReceiverProxy, error) {
	orderflowSigner, err := signature.NewRandomSigner()
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM([]byte(config.CACertPath)); !ok {
		return nil, errors.New("could not parse cacert")
	}

	cert, err := os.ReadFile(config.CertPath)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(config.CertKeyPath)
	if err != nil {
		return nil, err
	}

	certificate, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	localBuilder := rpcclient.NewClient(config.LocalBuilderEndpoint)

	limit := rate.Limit(config.MaxUserRPS)
	if config.MaxUserRPS == 0 {
		limit = rate.Inf
	}
	userAPIRateLimiter := rate.NewLimiter(limit, config.MaxUserRPS)
	prx := &ReceiverProxy{
		ReceiverProxyConstantConfig: config.ReceiverProxyConstantConfig,
		OrderflowSigner:             orderflowSigner,
		ClientCAs:                   caCertPool,
		PublicCertPEM:               cert,
		Certificate:                 certificate,
		localBuilder:                localBuilder,
		requestUniqueKeysRLU:        expirable.NewLRU[uuid.UUID, struct{}](requestsRLUSize, nil, requestsRLUTTL),
		replacementNonceRLU:         expirable.NewLRU[replacementNonceKey, int](replacementNonceSize, nil, replacementNonceTTL),
		userAPIRateLimiter:          userAPIRateLimiter,
	}
	maxRequestBodySizeBytes := DefaultMaxRequestBodySizeBytes
	if config.MaxRequestBodySizeBytes != 0 {
		maxRequestBodySizeBytes = config.MaxRequestBodySizeBytes
	}

	systemHandler, err := prx.SystemJSONRPCHandler(maxRequestBodySizeBytes)
	if err != nil {
		return nil, err
	}
	prx.SystemHandler = systemHandler

	userHandler, err := prx.UserJSONRPCHandler(maxRequestBodySizeBytes)
	if err != nil {
		return nil, err
	}
	prx.UserHandler = userHandler

	metadata := ConfighubBuilder{
		Name: prx.OrderflowSigner.Address().String(),
		IP:   "",
		OrderflowProxy: ConfighubOrderflowProxyCredentials{
			TLSCert:            string(prx.PublicCertPEM),
			EcdsaPubkeyAddress: prx.OrderflowSigner.Address(),
		},
	}
	metadataJson, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}

	prx.CertHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/octet-stream")
		_, err := w.Write(metadataJson)
		if err != nil {
			prx.Log.Warn("Failed to serve certificate", slog.Any("error", err))
		}
	})

	shareQeueuCh := make(chan *ParsedRequest, ReceiverProxyWorkerQueueSize)
	updatePeersCh := make(chan []ConfighubBuilder)
	prx.shareQueue = shareQeueuCh
	prx.updatePeers = updatePeersCh
	queue := ShareQueue{
		name:           prx.Name,
		log:            prx.Log,
		queue:          shareQeueuCh,
		updatePeers:    updatePeersCh,
		localBuilder:   prx.localBuilder,
		signer:         prx.OrderflowSigner,
		workersPerPeer: config.ConnectionsPerPeer,
	}
	go queue.Run()

	archiveQueueCh := make(chan *ParsedRequest, ReceiverProxyWorkerQueueSize)
	archiveFlushCh := make(chan struct{})
	prx.archiveQueue = archiveQueueCh
	prx.archiveFlushQueue = archiveFlushCh
	archiveHTTPClient := HTTPClientWithMaxConnections(config.ArchiveConnections)
	archiveClient := rpcclient.NewClientWithOpts(config.ArchiveEndpoint, &rpcclient.RPCClientOpts{
		Signer:     orderflowSigner,
		HTTPClient: archiveHTTPClient,
	})
	archiveQueue := ArchiveQueue{
		log:               prx.Log,
		queue:             archiveQueueCh,
		flushQueue:        archiveFlushCh,
		archiveClient:     archiveClient,
		blockNumberSource: NewBlockNumberSource(config.EthRPC),
	}
	go archiveQueue.Run()

	prx.peerUpdaterClose = make(chan struct{})
	go func() {
		for {
			select {
			case _, more := <-prx.peerUpdaterClose:
				if !more {
					return
				}
			case <-time.After(peerUpdateTime):
				err := prx.RequestNewPeers()
				if err != nil {
					prx.Log.Error("Failed to update peers", slog.Any("error", err))
				}
			}
		}
	}()

	// request peers on the first start
	_ = prx.RequestNewPeers()

	return prx, nil
}

func (prx *ReceiverProxy) Stop() {
	close(prx.shareQueue)
	close(prx.updatePeers)
	close(prx.archiveQueue)
	close(prx.archiveFlushQueue)
	close(prx.peerUpdaterClose)
}

func (prx *ReceiverProxy) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{prx.Certificate},
		MinVersion:         tls.VersionTLS13,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ClientCAs:          prx.ClientCAs,
		InsecureSkipVerify: true,
	}
}

func (prx *ReceiverProxy) RegisterSecrets(ctx context.Context) error {
	// TODO: should refresh CA and resign certificate
	return nil
}

func resolveDomainIPs(domain string) ([]string, error) {
	return []string{domain}, errors.New("not implemented")
}

func fetchBuilderMetadata(clientCAs *x509.CertPool, ip string) (ConfighubBuilder, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ClientCAs:  clientCAs,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s:14727/"))
	if err != nil {
		return ConfighubBuilder{}, err
	}

	defer resp.Body.Close()

	var builder ConfighubBuilder
	err = json.NewDecoder(resp.Body).Decode(&builder)
	if err != nil {
		return ConfighubBuilder{}, err
	}

	builder.IP = ip
	return builder, nil
}

// RequestNewPeers updates currently available peers from the builder config hub
func (prx *ReceiverProxy) RequestNewPeers() error {
	var builders []ConfighubBuilder

	for _, dns := range []string{"somedns.domain"} {
		ips, err := resolveDomainIPs(dns)
		if err != nil {
			// debug log
			continue
		}

		for _, ip := range ips {
			// TODO: skip already known
			builder, err := fetchBuilderMetadata(prx.ClientCAs, ip)
			if err != nil {
				// debug log
				continue
			}

			builders = append(builders, builder)
		}
	}

	prx.peersMu.Lock()
	prx.lastFetchedPeers = builders
	prx.peersMu.Unlock()

	select {
	case prx.updatePeers <- builders:
	default:
	}
	return nil
}

// FlushArchiveQueue forces the archive queue to flush
func (prx *ReceiverProxy) FlushArchiveQueue() {
	prx.archiveFlushQueue <- struct{}{}
}
