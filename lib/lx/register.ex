defmodule Lx.Register do
  @moduledoc """
  Register for workers to store state(s).

  A worker can create its own namespace by using __MODULE__ as a Lx.Register name.

  ## Example

  ```elixir
  @name __MODULE__

  def fun(),
    do: Lx.Register.put(@name, key, val)

  def fun2(),
    do: Lx.Register.get(@name, key) -> val
  ```

  """
  require Logger
  use Agent

  @doc """
  Start an Lx.Register
  """
  def start_link(name) when is_atom(name),
    do: Agent.start_link(fn -> %{} end, name: name)

  @doc """
  Stop an Lx.Register
  """
  def stop(name) when is_atom(name),
    do: Agent.stop(name)

  @doc """
  Store a value for a given key; returns old value (or nil) in an Lx.Register
  """
  def put(name, key, value) when is_atom(name),
    do: Agent.get_and_update(name, fn x -> {Map.get(x, key), Map.put(x, key, value)} end)

  @doc """
  Retrieve a value for given key from an Lx.Register
  """
  def get(name, key) when is_atom(name),
    do: Agent.get(name, fn x -> Map.get(x, key, nil) end)

  @doc """
  Delete a key,value pair in an Lx.Register; returns the value
  """
  def del(name, key) when is_atom(name),
    do: Agent.get_and_update(name, fn x -> {Map.get(x, key), Map.delete(x, key)} end)

  @doc """
  Delete a key,value pair; returns the value
  """
  def get_and_delete(name, key) when is_atom(name),
    do: Agent.get_and_update(name, fn x -> {Map.get(x, key), Map.delete(x, key)} end)
end
