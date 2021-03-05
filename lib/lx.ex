defmodule Lx do
  @moduledoc """
  Documentation for `Lx`.
  """

  @doc """
  Custom log formatter for Logger
  """
  def format(level, msg, ts, meta) do
    cmd = Keyword.get(meta, :cmd, "unknown")
    tstamp = format_ts(ts)
    pad = if String.length("#{level}") == 5, do: "", else: " "

    "#{tstamp} #{cmd} [#{pad}#{level}] #{msg}\n"
  rescue
    _ -> "oops"
  end

  def format_ts(ts) do
    {{year, month, day}, {hour, minute, second, ms}} = ts
    "#{year}#{month}#{day}T#{hour}:#{minute}:#{second}.#{ms}"
  rescue
    _ -> DateTime.utc_now() |> to_string() |> String.replace(["-", " "], "")
  end
end
