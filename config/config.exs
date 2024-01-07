import Config

config :zerossl,
  access_key: "99999999999999999999999999999999",
  user_email: "myfancy-email@gmail.com",
  cert_domain: "myfancy-domain.com",
  certfile: "./cert.pem",
  keyfile: "./key.pem",
  update_handler: nil

import_config "#{config_env()}.exs"
