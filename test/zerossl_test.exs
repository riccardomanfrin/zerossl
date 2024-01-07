defmodule ZerosslTest do
  use ExUnit.Case

  defmodule UpdateHandler do
    @behaviour Zerossl.UpdateHandler
    def update(_key, cert) do
      pid = Application.get_env(:zerossl, :test_pid)
      send(pid, cert)
    end
  end

  test "Cert renewal" do
    Application.put_env(:zerossl, :test_pid, self())
    {key, cert} = Selfsigned.gen_cert("myfancydomain.com", 10)
    Certmgr.write_cert(key, cert)
    {_key, cert} = Certmgr.read_cert()
    assert Certmgr.days_left(cert) == 0
    Certmgr.manage_cert_renewal()
    {_key, cert} = Certmgr.read_cert()
    assert Certmgr.days_left(cert) == 363

    receive do
      cert_bin ->
        assert cert_bin == cert
    end
  end
end
