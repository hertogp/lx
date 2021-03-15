defmodule Lx.Cmd do
  require Logger

  def main([]) do
    Logger.error("Need a command")
  end

  def main([cmd | argv]) do
    Logger.info("main with #{cmd}, #{inspect(argv)}")
    mod = Module.concat(__MODULE__, String.capitalize(cmd))

    result =
      case Code.ensure_loaded(mod) do
        {:module, module} -> dispatch(module, argv)
        {:error, reason} -> Logger.error("Could not load app #{mod}: #{reason}")
      end

    case result do
      :ok -> :ok
      x when is_binary(x) -> IO.puts(x)
      x -> IO.inspect(x)
    end
  end

  defp dispatch(module, argv) do
    case function_exported?(module, :run, 1) do
      true -> apply(module, :run, [argv])
      false -> Logger.error("module #{module} has no run/1 method?")
    end
  end
end
