We try to benchmark `fetch_notes` and profile `rusk-wallet` binary to see where we bottleneck in terms of cache.

First we talk about profiling. There's two profiles we need to take look at

1. When the cache is not created and the wallet has to fetch ALL the notes and populate the cache
2. The wallet cache is already populated and we don't do that much file IO

The following profiling results are in order of the conditions mentioned above

1. ![flamegraph](https://github.com/dusk-network/wallet-cli/assets/41485688/869742e5-fcae-41c3-b528-a945df02c47b)

So we see `<dusk_wallet::clients::StateStore as dusk_wallet_core::StateClient>::fetch_notes` 92.55% with MAX_ADDRESSES = 255

Now if we just run the binary again (the cache is created now). fetch_notes latency is neglegible because cache is created.


2. ![flamegraph](https://github.com/dusk-network/wallet-cli/assets/41485688/fce05349-6b25-4635-990d-8ebf179729e6)

So now we isolate `fetch_notes` and benchmark it using criteron. You can do it yourself with checking out this branch and running `cargo bench` 

Criteron runs the `fetch_notes` multiple times to benchmark it so we don't account for the latency of the first fetch and cache population. Only 
flamegraph helps us spot that.

We benchmark `MAX_ADDRESSES = 255, 200, 100, 1`

So the only relevant iteration for us is the first iteration because min iteratos criteron supports is 10.

<img width="1072" alt="Screenshot 2023-06-07 at 12 53 39 PM" src="https://github.com/dusk-network/wallet-cli/assets/41485688/79f1d8c8-c5bb-4c38-b35f-7eaebe5aa00c">

The outlier here is the 357.5 one which is probably the first iteration. Here is the Average absolute deviation from the mean for all the addresses. 
<img width="945" alt="Screenshot 2023-06-07 at 1 09 03 PM" src="https://github.com/dusk-network/wallet-cli/assets/41485688/8da24f7f-a167-4248-aeaa-413de972e7a7">
<img width="1072" alt="Screenshot 2023-06-07 at 12 53 39 PM" src="https://github.com/dusk-network/wallet-cli/assets/41485688/2c1be830-9afd-48ba-8aa5-b46f61dd8a12">
<img width="943" alt="Screenshot 2023-06-07 at 1 09 11 PM" src="https://github.com/dusk-network/wallet-cli/assets/41485688/32d8db65-6f62-4f11-9b7e-8d42f037d5fe">
<img width="971" alt="Screenshot 2023-06-07 at 1 09 16 PM" src="https://github.com/dusk-network/wallet-cli/assets/41485688/33eb3c38-3c3c-48ae-bb9a-2d6abcb62003">
<img width="1035" alt="Screenshot 2023-06-07 at 1 09 22 PM" src="https://github.com/dusk-network/wallet-cli/assets/41485688/c228545e-2b52-4850-a6a6-3874576ca99d">
