defmodule Lx.Cmd.Help do
  @moduledoc """
  Help on commands and then some!

  """

  require Logger

  @doc """
  run
  """
  def run(argv) do
    Logger.info(argv)
    Logger.info("commands are: " <> (cmd_map() |> Map.keys() |> Enum.join(", ")))

    case argv do
      [] -> list_cmds()
      [cmd | _] -> usage(cmd)
    end

    :ok
  end

  defp list_cmds() do
    cmd = Map.keys(cmd_map()) |> Enum.join(", ")

    """

    Usage:

      ./lx help <cmd>

      <cmd> is one of: #{cmd}
    """
  end

  defp usage(cmd) do
    mod = cmd_map(cmd)

    case Code.fetch_docs(mod) do
      {:error, _} -> Logger.error("unknown command #{cmd}")
      docs -> show(docs)
    end
  end

  defp show(docs) do
    case elem(docs, 4) do
      :none -> IO.puts("\nNo module documentation available")
      help -> IO.puts("\n" <> help["en"] <> "\n")
    end
  end

  # get all Lx.Cmd.<cmd> modules in a map
  defp cmd_map() do
    :application.get_key(:lx, :modules)
    |> elem(1)
    |> Enum.filter(fn mod -> String.contains?("#{mod}", "Lx.Cmd.") end)
    |> Enum.map(fn mod -> {Module.split(mod) |> List.last() |> String.downcase(), mod} end)
    |> Enum.reduce(%{}, fn {cmd, mod}, map -> Map.put(map, cmd, mod) end)
  end

  defp cmd_map(cmd) do
    cmd_map()
    |> Map.get(cmd, nil)
  end
end
