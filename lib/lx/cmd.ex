defmodule Lx.Cmd do
  @moduledoc """
  Run a requested command.

  A command must implement:
  - setup/1, setups the module (if needed) and parses argv into {opts, args}.
  - run/2, that takes a single arg and a options keyword list
    - is run inside an Task.async with a 10s timeout
    - returns either {:ok, result} or {:error, arg, reason}
    - if the task timesout, it is killed and its result will be {:exit, :timeout}
  - report/2, handles the results and options keyword list
    - results is a list of [{arg, result}, ..]

  TODO:
  - change run_async so it polls the tasks every 100ms for a total of 10sec
    yield_many returns:
    + {:ok, result}    = task completed successfully
    + {:exit, reason}  = task crashed for some reason
    + nil              = task not finished yet

  """
  require Logger

  @task_timeout 5_500
  @pbar_length 50

  @cmd_opts [
    debug: :boolean,
    quiet: :boolean,
    csv: :boolean
  ]

  @cmd_aliases [
    d: :debug,
    q: :quiet,
    c: :csv
  ]

  def main([]) do
    Logger.error("Need a command")
  end

  def main([cmd | argv]) do
    # TODO: level should be set via cli option lx wide...
    Lx.Msg.start(level: :debug, pbar: true)

    {opts, targets, invalid} = OptionParser.parse(argv, strict: @cmd_opts, aliases: @cmd_aliases)

    {dbg, opts} = Keyword.pop(opts, :debug, false)

    if dbg,
      do: Logger.configure_backend(:console, level: :debug),
      else: Logger.configure_backend(:console, level: :info)

    invalid
    |> Enum.map(fn x -> Logger.notice("ignoring unknown option #{inspect(x)}") end)

    Process.flag(:trap_exit, true)
    Lx.Cmd.Control.start_link(50)

    # Original
    # --------
    case dispatch(cmd, targets, opts) do
      {:error, reason} ->
        # Lx.Msg.error("command #{cmd} failed: #{reason}")
        Logger.error("command #{cmd} failed: #{reason}")

      x ->
        IO.inspect(x, label: :original)
        Logger.info("all done")
    end

    ## TODO:
    # - handle cmd setup/teardown, maybe here or in Lx.Cmd.Control?
    # - a worker may:
    #   1. timeout -> not freed up, howto correlate with its target
    #   2. die -> not freed up, howto correlate with its target
    #   3. complete -> returns result as ok/error tuple
    mod = module(cmd)

    targets
    |> stream_targets()
    |> Stream.map(fn target -> test(mod, cmd, target, opts) end)
    |> Enum.to_list()
    |> yield_until(500)
    |> Enum.map(fn {task, res} -> res || Task.shutdown(task, :brutal_kill) end)

    # |> IO.inspect(label: :result)
  end

  defp module(cmd) do
    module = Module.concat(__MODULE__, String.capitalize(cmd))

    case Code.ensure_loaded(module) do
      {:error, :nofile} ->
        {:error, "command not supported"}

      {:error, reason} ->
        {:error, reason}

      {:module, module} ->
        module
    end
  end

  # module for cmd was nog found
  def test({:error, reason}, cmd, target, _opts) do
    Task.completed({:error, {cmd, target, reason}})
  end

  def test(mod, cmd, target, opts) do
    if Lx.Cmd.Control.permit() do
      Task.async(fn -> apply(mod, :run, [target | opts]) end)
      |> Lx.Cmd.Control.start()
    else
      Process.sleep(500)
      test(mod, cmd, target, opts)
    end
  end

  defp dispatch(cmd, [], _opts),
    do: {:error, "missing targets for #{cmd}"}

  defp dispatch(cmd, targets, opts) do
    module = Module.concat(__MODULE__, String.capitalize(cmd))

    case Code.ensure_loaded(module) do
      {:error, :nofile} ->
        {:error, "command not supported"}

      {:error, reason} ->
        {:error, reason}

      {:module, module} ->
        {args, opts} = execp(targets, module, :setup, opts)

        args
        |> run_async(module, :run, opts)
        |> execp(module, :report, opts)
    end
  end

  defp execp(args, module, fun, opts) do
    case function_exported?(module, fun, 2) do
      true -> apply(module, fun, [args, opts])
      false -> {args, opts}
    end
  end

  defp run_async(args, module, fun, opts) do
    args
    |> stream_targets
    |> Enum.map(fn arg -> Task.async(fn -> apply(module, fun, [arg | opts]) end) end)
    |> yield_until(@task_timeout)
    |> Enum.map(fn {task, res} ->
      res || Task.shutdown(task, :brutal_kill) || {:error, "task brutally killed"}
    end)
    |> then(fn results -> List.zip([args, results]) end)
  end

  defp yield_until(tasks, max_time) do
    state =
      tasks
      |> Enum.reduce(%{}, fn task, acc -> Map.put(acc, task.ref, {task, nil}) end)
      |> loop_until(tasks, max_time)

    # return results in the same order as given tasks
    for task <- tasks,
        do: Map.get(state, task.ref)
  end

  defp loop_until(state, _running, time) when time <= 0 do
    progress_bar(0)
    IO.write(:standard_error, " - stopping, out of time\n")
    state
  end

  defp loop_until(state, [], time) do
    progress_bar(time)
    IO.write(:standard_error, " - all workers are done\n")
    state
  end

  defp loop_until(state, running, time) do
    # still have time and some workers running
    # progress_bar(Enum.count(running), time)
    progress_bar(time)
    millisec = 100

    {running, results} =
      running
      |> Task.yield_many(millisec)
      |> Enum.split_with(fn {_, r} -> r == nil end)

    running = running |> Enum.map(fn {t, _} -> t end)

    results
    |> Enum.reduce(state, fn {task, res}, acc -> Map.put(acc, task.ref, {task, res}) end)
    |> loop_until(running, time - millisec)
  end

  defp progress_bar(time) do
    done = @task_timeout - time
    divisor = 100 / @pbar_length
    percent = round(100 * done / @task_timeout)
    completed = round(percent / divisor)
    remaining = @pbar_length - completed

    pbar =
      IO.ANSI.format(
        [
          IO.ANSI.clear_line(),
          "\rTime ",
          :green_background,
          :black,
          String.duplicate("x", completed),
          :white_background,
          :red,
          String.duplicate("-", remaining),
          :reset,
          " #{percent}%",
          ", #{time} ms remaining",
          ", #{Lx.Cmd.Control.active()} workers active"
        ],
        true
      )

    IO.write(:standard_error, pbar)
  end

  @doc """
  Turn the argument list into a Stream of arguments, expanding prefixes to IP's

  Caller can consume the stream by calling (e.g.) Stream.chunk_every/2 followed
  by a Enum call.

  """
  def stream_targets(args),
    do: stream_targets(args, [])

  def stream_targets([], acc) do
    acc
    |> Stream.map(fn x -> "#{x}" end)
  end

  def stream_targets([head | rest], acc) do
    acc =
      case Pfx.parse(head) do
        {:ok, pfx} -> pfx
        _ -> [head]
      end
      |> Stream.concat(acc)

    stream_targets(rest, acc)
  end
end
