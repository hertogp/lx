defmodule Lx.Cmd.Control do
  use Agent

  @max_active 5

  # Lx.Cmd.Control needs to:
  # - keep track of worker pid's launched
  # - correlate timed out workers with their argument given
  # - correlate killed workers with their argument given
  # - keep track of the number of running workers
  # - enforce only @max_active are really active
  def start_link(_initial_value) do
    Agent.start_link(fn -> %{} end, name: __MODULE__)
  end

  def permit do
    Agent.get(__MODULE__, & &1) |> Enum.count() < @max_active
  end

  def active do
    # Agent.get(__MODULE__, & &1) |> Enum.count()
    Agent.get(__MODULE__, & &1)
    |> Map.filter(fn {pid, _} -> Process.alive?(pid) end)
    |> tap(fn _state -> Agent.update(__MODULE__, & &1) end)
    |> Enum.count()
  end

  def start(task) do
    Agent.update(__MODULE__, &Map.put(&1, task.pid, 1))
    task
  end

  def done(pid) do
    Agent.update(__MODULE__, &Map.delete(&1, pid))
  end
end
