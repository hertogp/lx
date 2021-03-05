defmodule Lx.Cmd.Ping do
  require Logger

  @cmd [cmd: "ping"]

  Logger.metadata(@cmd)

  def run(argv) do
    Logger.info("argv: #{inspect(argv)}", @cmd)
    Logger.warn("argv: #{inspect(argv)}")
    Logger.error("argv: #{inspect(argv)}")
    Logger.debug("argv: #{inspect(argv)}")
    IO.inspect(Logger.metadata())
    log(:info, "argv: #{inspect(argv)}")
    log(:warn, "argv: #{inspect(argv)}")
    log(:error, "argv: #{inspect(argv)}")
    log(:debug, "argv: #{inspect(argv)}")
  end

  def log(level, msg) do
    case level do
      :info -> Logger.info("[ping] " <> msg)
      :warn -> Logger.warn("[ping] " <> msg)
      :error -> Logger.error("[ping] " <> msg)
      :debug -> Logger.debug("[ping] " <> msg)
    end
  end
end
