import Config

config :zerossl,
  user_email: "myfancy-email@gmail.com",
  account_key: "99999999999999999999999999999999",
  cert_domain: "myfancy-domain.com",
  certfile: "./cert.pem",
  keyfile: "./key.pem",
  update_handler: nil,
  port: 80,
  addr: "0.0.0.0"

import_config "#{config_env()}.exs"
