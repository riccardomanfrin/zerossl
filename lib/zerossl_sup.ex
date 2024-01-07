defmodule ZerosslSup do
  @moduledoc """
  Zerossl Supervisor managing the Certmgr genserver
  """
  use Application

  defmodule UpdateHandler do
    @callback update(key :: binary(), cert :: binary()) :: :ok
  end

  def start(_type, _args) do
    children = [Certmgr.child_spec([])]
    Supervisor.start_link(children, strategy: :one_for_one, name: ZerosslSup)
  end
end
