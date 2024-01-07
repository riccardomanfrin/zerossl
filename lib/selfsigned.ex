defmodule Selfsigned do
  @moduledoc """
  Module to issue certificate with arbitrary lifetime

  This module serves testing purposes.
  """

  @default_validity_seconds 365 * 24 * 60 * 60

  @doc """
  Generate a self-signed 2048 bit RSA key X509 certificate for testing purposes
  """
  @spec gen_cert(hostname :: binary(), validity_seconds :: integer()) ::
          {key :: binary(), cert :: binary()}
  def gen_cert(hostname, validity_seconds \\ @default_validity_seconds) do
    key_size = 2048
    name = hostname
    hostnames = [hostname]
    private_key = X509.PrivateKey.new_rsa(key_size)

    not_before = DateTime.now!("Etc/UTC")
    not_after = DateTime.add(not_before, validity_seconds, :second)

    validity = X509.Certificate.Validity.new(not_before, not_after)

    certificate =
      X509.Certificate.self_signed(
        private_key,
        "/CN=#{name}",
        template: :server,
        extensions: [
          subject_alt_name: X509.Certificate.Extension.subject_alt_name(hostnames)
        ],
        validity: validity
      )

    {X509.PrivateKey.to_pem(private_key), X509.Certificate.to_pem(certificate)}
  end
end
