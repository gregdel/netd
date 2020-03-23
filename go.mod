module github.com/gregdel/netd

go 1.14

replace github.com/gregdel/nft => ../nft

replace github.com/google/nftables => ../nftables

require (
	github.com/google/nftables v0.0.0-20200316075819-7127d9d22474
	github.com/gregdel/nft v0.0.0-20200311121651-707a452b35bb
	github.com/kr/pretty v0.2.0
)
