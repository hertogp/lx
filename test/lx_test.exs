defmodule LxTest do
  use ExUnit.Case
  doctest Lx

  test "greets the world" do
    assert Lx.hello() == :world
  end
end
