defmodule Certmgr do
  @moduledoc """
  Manager of the status of the certificate. This genserver maintains
  a timer to renew the certificate one day ahead of expiration.

  If a certificate is not found in path, it is immediately generated.

  Additionally, by specifying an `:update_handler` in the `:zerossl`
  configuration it's possible for an application to get notified about
  certificate generation/renewal.
  """
  use GenServer

  require Logger

  @doc """
  Childspec of Certmgr genserver
  """
  def child_spec(arg) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [arg]}
    }
  end

  def start_link(args) do
    GenServer.start_link(__MODULE__, args, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    manage_cert_renewal()
    {:ok, opts}
  end

  @impl true
  def handle_info(_info, state) do
    manage_cert_renewal()
    {:noreply, state}
  end

  @doc """
  Read key and certificate from file, or raise an error if
  it does not find them
  """
  def read_cert() do
    keyfile = Application.get_env(:zerossl, :keyfile)
    certfile = Application.get_env(:zerossl, :certfile)

    with {:filenames, {true, true}} <- {:filenames, {keyfile != nil, certfile != nil}},
         {:ok, key} <- File.read(keyfile),
         {:ok, cert} <- File.read(certfile) do
      Logger.debug("Loaded certfile #{certfile} and keyfile #{keyfile}")
      {key, cert}
    else
      {:filenames, _} ->
        raise("Missing certificate / key filename paths")

      {:error, _} ->
        Logger.info("File #{keyfile} or #{certfile} missing")
        {nil, nil}
    end
  end

  @doc """
  Write key and certificate to the files specified by the config
  """
  def write_cert(key, cert) do
    keyfile = Application.get_env(:zerossl, :keyfile)
    certfile = Application.get_env(:zerossl, :certfile)
    Logger.debug("Storing certfile #{certfile} and keyfile #{keyfile}")

    if certfile != nil and keyfile != nil do
      File.write(certfile, cert)
      File.write(keyfile, key)
    end

    :ok
  end

  @days_milliseconds 24 * 60 * 60 * 1000
  @doc """
  Manage the certificate renewal by checking it's not_before and not_after Validities.

  Every time the certificate has less than one day of validity, a renewal is issued.
  Otherwise a timer is set to wait until the moment such last day of validity is reached,
  to trigger the renewal again.
  """
  @spec manage_cert_renewal() :: :ok
  def manage_cert_renewal() do
    with {key, cert} when not is_nil(key) and not is_nil(cert) <- read_cert(),
         days_left <- days_left(cert) do
      case days_left <= 0 do
        true ->
          renew_certificate()
          manage_cert_renewal()

        false ->
          Logger.debug("Valid cert, renewing key/cert in #{days_left} days")
          Process.send_after(self(), :work, days_left * @days_milliseconds)
          :ok
      end
    else
      _ ->
        renew_certificate()
        manage_cert_renewal()
    end
  end

  defp renew_certificate() do
    user_email = Application.get_env(:zerossl, :user_email)
    account_key = Application.get_env(:zerossl, :account_key)
    domain = Application.get_env(:zerossl, :cert_domain)

    Logger.debug("Renewing certificate now!")

    {cert_priv_key, public_cert} =
      case Application.get_env(:zerossl, :selfsigned, false) do
        true -> Selfsigned.gen_cert(domain)
        false ->
          case user_email do
            nil -> Acmev2.gen_cert_from_account_key(account_key, domain)
              _ -> Acmev2.gen_cert_from_email(user_email, domain)

          end
        end

    write_cert(cert_priv_key, public_cert)
    notify_update_handler(cert_priv_key, public_cert)
  end

  defp notify_update_handler(cert_priv_key, public_cert) do
    case Application.get_env(:zerossl, :update_handler) do
      nil -> :ok
      module -> module.update(cert_priv_key, public_cert)
    end
  end

  def days_left(cert) do
    {:Validity, {:utcTime, not_before}, {:utcTime, not_after}} =
      hd(:public_key.pem_decode(cert))
      |> :public_key.pem_entry_decode()
      |> X509.Certificate.validity()

    <<year::binary-size(4), month::binary-size(2), day::binary-size(2), hour::binary-size(2),
      minute::binary-size(2), _rest::binary>> = "20#{not_before}"

    not_before =
      DateTime.new!(
        Date.new!(i2s(year), i2s(month), i2s(day)),
        Time.new!(i2s(hour), i2s(minute), 0),
        "Etc/UTC"
      )

    <<year::binary-size(4), month::binary-size(2), day::binary-size(2), hour::binary-size(2),
      minute::binary-size(2), _rest::binary>> = "20#{not_after}"

    not_after =
      DateTime.new!(
        Date.new!(i2s(year), i2s(month), i2s(day)),
        Time.new!(i2s(hour), i2s(minute), 0),
        "Etc/UTC"
      )

    # Logger.info("Not before: #{inspect(not_before)}, not after: #{inspect(not_after)}")

    now = DateTime.now!("Etc/UTC")

    case DateTime.compare(not_before, now) == :lt and DateTime.compare(now, not_after) == :lt do
      true -> DateTime.diff(not_after, now, :day) - 1
      false -> 0
    end
  end

  defp i2s(str) when is_binary(str), do: String.to_integer(str)
end
