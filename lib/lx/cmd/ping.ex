defmodule Lx.Cmd.Ping do
  alias Lx.Msg
  @t0 500
  @t1 2000
  def run(arg) do
    Msg.level(:debug)
    Process.sleep(:random.uniform(@t0) * 1)
    Msg.error("arg: #{arg}")
    Process.sleep(:random.uniform(@t0) * 1)
    Msg.warn("arg: #{arg}")
    Process.sleep(:random.uniform(@t0) * 1)
    Msg.note("arg: #{arg}")
    Process.sleep(:random.uniform(@t0) * 1)
    Msg.info("arg: #{arg}")
    Process.sleep(:random.uniform(@t0) * 1)
    Msg.verbose("arg: #{arg}")
    Process.sleep(:random.uniform(@t0) * 1)
    Msg.debug("arg: #{arg}")
    Process.sleep(@t1)
    Msg.done()
    Process.sleep(@t1)
  end
end
