defmodule Lx.Cmd.Ping do
  alias Lx.Msg
  require Logger
  @t0 500
  @t1 300
  def run(arg) do
    Msg.level(:debug)
    Process.sleep(:rand.uniform(@t0) * 1)
    Msg.error(%{arg: "#{arg}"})
    Process.sleep(:rand.uniform(@t0) * 1)
    Msg.warn("arg: #{arg}")
    Process.sleep(:rand.uniform(@t0) * 1)
    Msg.note("arg: #{arg}")
    Process.sleep(:rand.uniform(@t0) * 1)
    Msg.info("arg: #{arg}")
    Process.sleep(:rand.uniform(@t0) * 1)
    Msg.verbose("arg: #{arg}")
    Process.sleep(:rand.uniform(@t0) * 1)
    Msg.debug("arg: #{arg}")
    Process.sleep(@t1)
    Msg.done()
    :ok
  end
end
