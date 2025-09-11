
# Zerossl / Letsencrypt client library with autorenewal management

Zerossl is a Elixir library to automatically manage and refresh your Zerossl and Letsencrypt certificates natively, without the need for extra applications like [acme.sh](https://github.com/acmesh-official/acme.sh)  bash script or [certbot](https://certbot.eff.org/) clients.
The client implements the [ACME(v2) rfc8555](https://datatracker.ietf.org/doc/html/rfc8555) `http-01` challenge auth mechanism to issue and refresh a genuine certificate against [Zerossl](https://zerossl.com/)

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed by adding `zerossl` 
to your list of dependencies in `mix.exs`:

  
```elixir
def  deps  do
[
  {:zerossl, "~> 1.1.2"}
]
end
```

The `x509` leveraged for key management has some OTP dependencies to match. Read [here](https://hexdocs.pm/x509/readme.html) for more information.

## Configuration

In your `config.exs` or `prod.exs` add the following config:

```elixir
config  :zerossl,
  provider: :letsencrypt,
  cert_domain:  "myfancy-domain.com",
  certfile:  "./cert.pem",
  keyfile:  "./key.pem"
```
where
* `provider` is `:zerossl` (default), `:letsenctypt` or `:letsencrypt_test`
* `cert_domain` is the domain that resolves your software application project, and for which you want to issue the certificate
* `certfile` and `keyfile` are the places where you want to store your certificate and key respectively.

Key and certificate are always stored on FS to avoid regenerating them upon reboot.

### Additional optional config
* `port`, [default: `80`] optional listening port for serving the well-known secret token.
* `addr`, [default: `0.0.0.0`] optinal listenening ip address for serving well-known secret token.
* `selfsigned` [default: `false`]: forces "dryrun" selfsigned certificate generation without an actual exchange with a certificate provider (used for testing).
* `update_handler` [default: `nil`]: permits to specify a module that implements the `Zerossl.UpdateHandler` behavior to get notifications when the certificate is renewed. This can be used as trigger to reload a listening HTTPs server with the new certificate/key. The handler is always invoked upon start of the process: subordinating the start of the HTTPs server to the call by this handler is legitimate.
* `user_email` email used to request EABs;
* `account_key`: for Zerossl certificate provider it is possible to use an account_key in place of the `:user_email` to retrieve EAB credentials [getting EAB credentials](https://zerossl.com/documentation/acme/generate-eab-credentials/). 

The `:user_email` and `:account_key` are not required for providers that do not requre EAB (such as letsencrypt). When the provider requires EAB and none of these settings keys are configured, the application raises an exception.

# Instructions

## Prerequisites

1. docker
2. python3 virtual env (for tests)

## Virtual env

```bash
source venv/bin/activate
pip install -r requirements.txt
```

## Test

```bash
python -m unittest discover tests
```

## Coverage

Replace firefox with anythinggoes browser.

```bash
pip install coverage
coverage run -m unittest discover tests
coverage report
coverage html
firefox htmlcov/index.html
```

## Build

```bash
./build.sh
```

## Run

```bash
run.sh
```

# Additional context

### Why flask

I had initially done the API by subclassing BaseHTTPRequestHandler to basically have empty `requirements.txt` (which I like as a general approach).

Afterall this was supposed to be for a friend so, whatever works...

Than I saw you mentioned Flask in `test.sh` so I "upgraded" to that just to demo its usage and pip usage along with it.

### Persistency (since you mentioned)

I added some sqlite3 persistency to avoid having to submit the CSVs on restart and to keep track of the records.
At the same time and for sake of tests I opted in a private "flush" API to clean the database. A less invasive approach would have been to physically delete the database file. Anyhow that path can be kept private and excluded by
an hypothetical reverse proxy.

Even though I keep the records in the database, I added the instant balance sums to avoid iterating over the records every time I have to calculate the balance. This comes at the cost of keeping two sources of truth (the database and the in-memory sums). In case of misalignment, restarting the service will fix it (somehow*).

### Approach to partial failures

When uploading data from CSV, if there are invalid lines (as in the example), the record is skipped and a warning is logged. This logic might be not ok because if the invalid line was not a comment, but a malformed record, the user would not be notified.

# Shortcomings

1. I'm serving the app directly not behind nginx / gunicorn etc.. which is not ideal architecturally

2. I used SQlite to keep things simple since the amount of data is supposingly small. For higher volume there might be better choices (e.g. postgres, redis, etc..)

3. Partial failures are allowed. In real world this might not be ok, and there might be need for more pre-validation or in the worst case a rollback. For APIs of these kind I like the apply/commit approach where you can stash your changes live and see the result, and if things are ok you can consolidate/persist them (for example I do this for networking at work, to avoid losing the VMs, along with a confirmation API to prove you can reach the VM after live network reconfiguration.. ).

# If I had more time I would 

1. add a proper logging framework
2. add more testcases if possible (maybe completing coverage of `tax_tracker.py` with missed lines 51 and 52)
3. add more error handling and pre-validation to the API endpoints 
4. reduce the amount of code within try/catch statements if possible
5. add more comments/doc to the code
6. add a docker-compose yaml
7. return a structured log of the lines of the CSV that failed to be parsed in the data upload API HTTP response.
