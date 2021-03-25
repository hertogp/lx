defmodule Lx.Msg do
  @moduledoc """
  Sends messages to the console for different levels:
  error, warn, note, info (-v) , verbose (-vv), debug (-d),
  with note being the default level.

  Also, when progress is true, Lx.Msg will maintain a progress bar as the last line of output
  on the console.

  """
  use GenServer
  alias IO.ANSI

  @levels %{error: 0, warn: 1, note: 2, info: 3, verbose: 4, debug: 5}
  @colors %{error: ANSI.red(), warn: ANSI.yellow(), debug: ANSI.cyan()}
  @default_level :note

  # Client API

  def start(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def level(),
    do: GenServer.call(__MODULE__, {:level, :get})

  def level(level),
    do: GenServer.call(__MODULE__, {:level, :set, level})

  def flush() do
    GenServer.cast(__MODULE__, {self(), :flush})
  end

  def done() do
    GenServer.call(__MODULE__, :done)
  end

  def error(msg),
    do: GenServer.cast(__MODULE__, {self(), :error, msg})

  def warn(msg),
    do: GenServer.cast(__MODULE__, {self(), :warn, msg})

  def note(msg),
    do: GenServer.cast(__MODULE__, {self(), :note, msg})

  def info(msg),
    do: GenServer.cast(__MODULE__, {self(), :info, msg})

  def verbose(msg),
    do: GenServer.cast(__MODULE__, {self(), :verbose, msg})

  def debug(msg),
    do: GenServer.cast(__MODULE__, {self(), :debug, msg})

  # Server (callbacks)

  def init(opts) do
    level = Keyword.get(opts, :level, @default_level)
    {:ok, update_level(%{}, level)}
  end

  def handle_call({:level, :get}, _from, state) do
    {:reply, state.level, state}
  end

  def handle_call({:level, :set, level}, _from, state) do
    {:reply, :ok, update_level(state, level)}
  end

  def handle_call(:done, {pid, _ref}, state) do
    {:reply, :ok, flush_buf(pid, state)}
  end

  def handle_call({level, msg}, {pid, _ref}, state) do
    if @levels[level] > @levels[state.level],
      do: {:reply, :ok, state},
      else: {:reply, :ok, update_state({level, msg}, pid, state)}
  end

  def handle_cast({pid, :flush}, state) do
    state = flush_buf(pid, state)
    {:noreply, state}
  end

  def handle_cast({pid, level, msg}, state) do
    state =
      if @levels[level] > @levels[state.level],
        do: state,
        else: update_state({level, msg}, pid, state)

    {:noreply, state}
  end

  # Private helpers

  defp update_state(entry, pid, state) do
    buf = Map.get(state, pid, [])
    Map.put(state, pid, [entry | buf])
  end

  defp flush_buf(pid, state) do
    {buf, state} = Map.pop(state, pid, [])
    Enum.each(buf, &outputp2/1)
    state
  end

  defp update_level(state, level) do
    if Map.has_key?(@levels, level),
      do: Map.put(state, :level, level),
      else: Map.put(state, :level, @default_level)
  end

  defp outputp2({level, msg}) do
    progress(:clear)
    nocolor = ANSI.default_color()
    color = Map.get(@colors, level, "")

    level =
      if level == :verbose,
        do: "+info",
        else: String.pad_leading("#{level}", 5)

    msg = "#{inspect(msg)}"
    IO.puts("#{color}[#{level}] #{msg}#{nocolor}")
    progress(:write, 3, 10)
  end

  defp outputp(level, msg) do
    progress(:clear)
    nocolor = ANSI.default_color()
    color = Map.get(@colors, level, "")

    level =
      if level == :verbose,
        do: "+info",
        else: String.pad_leading("#{level}", 5)

    msg = "#{inspect(msg)}"
    IO.puts("#{color}[#{level}] #{msg}#{nocolor}")
    progress(:write, 3, 10)
  end

  defp progress(:clear) do
    IO.write(:stdio, "\r" <> String.duplicate(" ", 80) <> "\r")
  end

  defp progress(:write, num, tot) do
    progress(:clear)
    bar = String.duplicate("#", num) |> String.pad_trailing(tot, " ")

    IO.write(:stdio, " Progress [#{bar}] #{num}/#{tot}\r")
  end
end
