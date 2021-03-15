defmodule Lx.Utils do
  @moduledoc """
  LX.Utils
  """

  def load_oids() do
    oids =
      from_lib("public_key/include/OTP-PUB-KEY.hrl") ++
        from_lib("public_key/include/PKCS-FRAME.hrl")

    extras = [
      # https://www.rfc-editor.org/rfc/rfc6962.txt - Certficate Transparancy
      {:signedCertificateTimestampList, {1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}},
      {:sctOscpPoison, {1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}},
      {:sctOscp4, {1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}},
      {:sctOscp5, {1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}},
      # https://cabforum.org/object-registry/
      {:CABFOrganizationValidated, {2, 23, 140, 1, 2, 2}},
      {:googleTrustServicesCP1_3, {1, 3, 6, 1, 4, 1, 11129, 2, 5, 3}}
    ]

    oids = oids ++ extras

    m = for {k, v} <- oids, into: %{}, do: {v, k}
    for {k, v} <- oids, into: m, do: {k, v}
  end

  # OIDs ----------------------------------------------------------------
  # - From X509/asn1/oid_import.ex
  # # From Record.Extractor
  def from_lib(file) do
    file
    |> from_lib_file()
    |> get_oids()
  end

  defp from_lib_file(file) do
    [app | path] = :filename.split(String.to_charlist(file))

    case :code.lib_dir(List.to_atom(app)) do
      {:error, _} ->
        raise ArgumentError, "lib file #{file} could not be found"

      libpath ->
        :filename.join([libpath | path])
    end
  end

  # Parse an Erlang header file without preprocessing, and extract any OID
  # definitions
  defp get_oids(file) do
    case :epp_dodger.parse_file(file) do
      {:ok, tree} ->
        tree
        |> Enum.map(&filter_and_map_oid/1)
        |> Enum.reject(&is_nil/1)

      other ->
        raise "error parsing file #{file}, got: #{inspect(other)}"
    end
  end

  # This clause matches a `-define()` with a tuple value; it returns a
  # name/value tuple if it turns out to be an OID, or nil otherwise
  defp filter_and_map_oid(
         {:tree, :attribute, _,
          {:attribute, {:atom, _, :define},
           [{:atom, _, name}, {:tree, :tuple, {:attr, _, [], _}, list}]}} = _x
       ) do
    # IO.inspect(x)

    # If all values in the tuple are integers; reconstruct the tuple
    # and return it with the name
    if Enum.all?(list, &match?({:integer, _, _}, &1)) do
      {
        name,
        list
        |> Enum.map(&elem(&1, 2))
        |> List.to_tuple()
      }
    else
      nil
    end
  end

  defp filter_and_map_oid(_), do: nil
end
