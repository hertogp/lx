defmodule Lx.Cmd do
  @moduledoc """
  Run a requested command.

  A command
  - MAY have an setup/1 function that is called with supplied args.
  - an init/1 function MUST return args to be supplied to the command's run/1 function
  - MUST have a run/1 method that takes a list of arguments
  - MUST return either {:ok, result} or {:error, reason}
  - MUST have a log/1 function wich is called with the result of its run/1 function

  """
  require Logger

  def main([]) do
    Logger.error("Need a command")
  end

  def main([cmd | argv]) do
    Lx.Msg.start(level: :note)
    Logger.info("main with #{cmd}, #{inspect(argv)}")
    module = Module.concat(__MODULE__, String.capitalize(cmd))

    case dispatch(module, argv) do
      {:error, reason} -> Logger.error("command #{cmd}: #{reason}")
      x -> x
    end
  end

  # run a command's init/1, Nx its run/1 (asynchrosnously) and its teardown/1
  defp dispatch(module, argv) do
    case Code.ensure_loaded(module) do
      {:error, reason} ->
        {:error, reason}

      {:module, module} ->
        argv
        |> execp(module, :setup)
        |> stream(module, :run)
        |> stream(module, :report)
        |> Stream.run()
        # Enum.into([])
        |> execp(module, :teardown)
    end
  end

  defp execp(argv, module, fun) do
    case function_exported?(module, fun, 1) do
      true -> apply(module, fun, [argv])
      false -> argv
    end
  end

  defp stream(argv, module, fun) do
    case function_exported?(module, fun, 1) do
      true ->
        Task.async_stream(argv, module, fun, [],
          ordered: false,
          on_timeout: :kill_task,
          max_concurrency: 100
        )

      false ->
        argv
    end
  end
end
