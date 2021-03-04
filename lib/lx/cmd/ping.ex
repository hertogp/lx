defmodule Lx.Cmd.Ping do
  require Logger

  Logger.metadata(cmd: __MODULE__)

  def run(argv) do
    Logger.info("argv: #{inspect(argv)}")
  end
end
