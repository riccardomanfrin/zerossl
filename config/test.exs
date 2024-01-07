import Config

config :zerossl,
  certfile: "priv/cert/selfsigned.pem",
  keyfile: "priv/cert/selfsigned_key.pem",
  selfsigned: true,
  update_handler: ZerosslTest.UpdateHandler
