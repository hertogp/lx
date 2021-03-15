defmodule Lx do
  @moduledoc """
  Documentation for `Lx`.
  """

  @cmd_width 6

  @doc """
  Custom log formatter for Logger
  """
  def format(level, msg, ts, meta) do
    cmd = format_cmd(meta) |> String.pad_trailing(@cmd_width)
    tstamp = format_ts(ts)
    level = String.pad_leading("#{level}", 5)

    "#{tstamp} #{cmd} [#{level}] #{msg}\n"
  rescue
    _ -> "*** error: Lx.format(#{inspect({level, msg, ts, meta})})"
  end

  def format_ts(ts) do
    {{year, month, day}, {hour, minute, second, _ms}} = ts
    "#{year}#{month}#{day}T#{hour}:#{minute}:#{second}"
  rescue
    _ -> DateTime.utc_now() |> to_string() |> String.replace(["-", " "], "")
  end

  def format_cmd(meta) do
    Keyword.get(meta, :module, "unknown")
    |> to_string()
    |> String.split(".")
    |> List.last()
    |> String.downcase()
  rescue
    _ -> to_string("ehm?")
  end
end
