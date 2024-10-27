
# Zerossl client library

Zerossl is a Elixir library to automatically manage and refresh your Zerossl and Letsencrypt certificates natively, without the need for extra applications like [acme.sh](https://github.com/acmesh-official/acme.sh)  bash script or [certbot](https://certbot.eff.org/) clients.
The client implements the [ACME(v2) rfc8555](https://datatracker.ietf.org/doc/html/rfc8555) `http-01` challenge auth mechanism to issue and refresh a genuine certificate against [Zerossl](https://zerossl.com/)

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed by adding `zerossl` 
to your list of dependencies in `mix.exs`:

  
```elixir
def  deps  do
[
  {:zerossl, "~> 1.1.1"}
]
end
```

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

