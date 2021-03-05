defmodule Lx.Cmd.Ietf do
  require Logger
  Logger.metadata(cmd: "ietf")
  IO.inspect(Logger.metadata())

  def run(argv) do
    Logger.metadata(cmd: "ietf")
    Logger.debug("argv: #{inspect(argv)}")
    func2("wow")
  end

  def func2(x) do
    Logger.info(x)
  end
end
