defmodule Lx.Cmd.Ietf do
  require Logger

  def run(argv) do
    Logger.debug("argv: #{inspect(argv)}")
    func2("wow")
  end

  def func2(x) do
    Logger.info(x)
  end
end
