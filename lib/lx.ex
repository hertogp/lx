defmodule Lx do
  @moduledoc """
  Documentation for `Lx`.
  """

  @doc """
  Custom log formatter for Logger
  """
  def format(level, msg, ts, meta) do
    # cmd = format_cmd(meta) |> String.pad_trailing(@cmd_width)
    cmd = format_cmd(meta)
    tstamp = format_ts(ts)
    level = String.pad_leading("#{level}", 5)

    "#{tstamp} #{cmd} [#{level}] #{msg}\n"
  rescue
    _ -> "*** error: Lx.format(#{inspect({level, msg, ts, meta})})"
  end

  def format_ts(ts) do
    {{year, month, day}, {hour, minute, second, _ms}} = ts

    # zero padding
    month = String.pad_leading("#{month}", 2, "0")
    day = String.pad_leading("#{day}", 2, "0")
    minute = String.pad_leading("#{minute}", 2, "0")
    second = String.pad_leading("#{second}", 2, "0")

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
