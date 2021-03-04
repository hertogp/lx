defmodule Lx.Cmd do
  require Logger

  def main(argv) do
    cmd = hd(argv) |> String.capitalize()
    mod = Module.concat(__MODULE__, cmd)

    case Code.ensure_loaded(mod) do
      {:module, module} -> dispatch(module, argv)
      {:error, reason} -> Logger.error(fn -> "Could not load app #{mod}: #{reason}" end)
    end
  end

  defp dispatch(module, [_ | argv]) do
    case function_exported?(module, :run, 1) do
      true -> apply(module, :run, [argv])
      false -> Logger.error(fn -> "module #{module} has no run/1 method?" end)
    end
  end
end
