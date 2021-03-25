defmodule Lx.Cmd.Ssl do
  @moduledoc """
  Worker that gathers and reports on a host's certificate chain (if any).
  """

  require Logger
  alias OptionParser

  @oids Lx.Utils.load_oids()
  @name __MODULE__
  @ssl_opts [
    versions: [:"tlsv1.1", :"tlsv1.2"],
    ciphers: :ssl.cipher_suites(:default, :"tlsv1.2"),
    depth: 99
  ]
  @cmd_opts [
    debug: :boolean,
    note: :boolean
  ]
  @cmd_aliases [
    d: :debug,
    n: :note
  ]

  @doc """
  Initialize module, parse arguments and prune argv to list of hosts
  """
  def setup(argv) do
    {parsed, args, invalid} = OptionParser.parse(argv, strict: @cmd_opts, aliases: @cmd_aliases)

    if Keyword.get(parsed, :debug, false),
      do: Logger.configure_backend(:console, level: :debug),
      else: Logger.configure_backend(:console, level: :info)

    invalid
    |> Enum.map(fn x -> Logger.debug("unknown option #{inspect(x)}") end)

    # partial_chain stores the certificate chain in this registry (key = hash of end cert)
    Lx.Register.start_link(@name)

    args
    |> Enum.uniq()
  end

  def teardown(_result),
    do: Lx.Register.stop(@name)

  @doc """
  Run a worker for a single argument
  """
  def run(hostname) do
    Logger.notice("running with #{inspect(hostname)}")

    host = to_charlist(hostname)

    ssl_opts =
      @ssl_opts
      |> Keyword.put(:partial_chain, &partial_chain/1)
      |> Keyword.put(:server_name_indication, host)

    result =
      with(
        {:connect, {:ok, sock}} <- {:connect, :ssl.connect(host, 443, ssl_opts)},
        {:cert, {:ok, der}} <- {:cert, :ssl.peercert(sock)},
        {:name, {:ok, {ip, port}}} <- {:name, :ssl.peername(sock)}
      ) do
        :ssl.close(sock)
        id = :crypto.hash(:sha256, der)

        chain =
          Lx.Register.get(@name, id)
          |> Enum.reverse()
          |> Enum.map(fn cert -> der_decode(cert) end)

        {:ok, {ip, port}, chain}
      else
        {:connect, {:error, reason}} ->
          {:error, "Could not connect to #{hostname} (#{inspect(reason)}})"}

        {:cert, error} ->
          {:error, "Could not get peercert for #{hostname} (#{inspect(error)}"}

        {:name, error} ->
          {:error, "Could not get peer name for #{hostname} (#{inspect(error)})"}

        error ->
          {:error, "** unknown error: #{inspect(error)}"}
      end

    {@name, hostname, result}
  end

  def report({:ok, result}),
    do: report(result)

  def report({:exit, reason}),
    do: Logger.error("exited: #{inspect(reason)}")

  def report({@name, hostname, {:error, reason}}),
    do: Logger.error("#{hostname} ** #{reason}")

  def report({@name, hostname, {:ok, {ip, port}, certs}}) do
    addr = Tuple.to_list(ip) |> Enum.join(".")
    Logger.info("[#{hostname}]  #{Enum.count(certs)}  certs @ #{addr}:#{port}")

    certs
    |> Enum.with_index()
    |> Enum.map(fn x -> report_cert(hostname, x) end)
  end

  defp report_cert(hostname, {cert, idx}) do
    msg =
      "subject=#{cert.subjectCommonname}" <>
        ", issuer=#{cert.issuerCommonname}" <>
        ", not_before=#{cert.not_before}" <>
        ", not_after=#{cert.not_after}"

    msg =
      case Map.get(cert, :_subjectAltName, []) do
        [] -> msg
        list -> msg <> ", altnames=#{Enum.join(list, ", ")}"
      end

    Logger.info("[#{hostname}] [#{idx}] #{msg}")
  end

  # Implementation

  defp partial_chain(certs) do
    # certs [Root CA, Intermediates (if any)..., End Certificate]
    # - register chain under fingerprint(End Certificate) & trust the Root CA
    id = :crypto.hash(:sha256, List.last(certs))
    Lx.Register.put(@name, id, certs)
    {:trusted_ca, List.first(certs)}
  end

  def der_decode(der) do
    {:OTPCertificate, cert, signatureAlgorithm, signature} =
      :public_key.pkix_decode_cert(der, :otp)

    {:OTPTBSCertificate, version, serialNumber, signature2, issuer, validity, subject,
     subjectPublicKeyInfo, issuerID, subjectID, extensions} = cert

    m = %{
      certSignatureAlgo: decode(signatureAlgorithm),
      certSignature: signature,
      version: decode(version),
      serialNumber: serialNumber,
      signature: decode(signature2),
      subjectPublicKeyInfo: decode(subjectPublicKeyInfo),
      issuerID: decode(issuerID),
      subjectID: decode(subjectID)
    }

    m =
      decode(issuer)
      |> Enum.reduce(m, fn {k, v}, acc ->
        Map.put(acc, String.to_atom("issuer" <> String.capitalize(k)), v)
      end)

    m =
      decode(subject)
      |> Enum.reduce(m, fn {k, v}, acc ->
        Map.put(acc, String.to_atom("subject" <> String.capitalize(k)), v)
      end)

    m =
      extensions
      |> Enum.map(fn x -> decode(x) end)
      |> Enum.reduce(m, fn {k, v}, acc ->
        Map.put(acc, String.to_atom("_#{k}"), v)
      end)

    {:Validity, not_before, not_after} = decode(validity)
    m = Map.put(m, :not_before, not_before)
    m = Map.put(m, :not_after, not_after)

    # {:ok, IO.inspect(m, label: :mapped)}
    m
  end

  # oid_name
  def oid_name(oid) when is_tuple(oid) do
    case @oids[oid] do
      nil -> Tuple.to_list(oid) |> Enum.join(".") |> (&"unknown OID #{&1}").()
      name -> String.split("#{name}", "-") |> List.last()
    end
  end

  # DECODE values -------------------------------------------------------
  def decode(nil), do: nil
  def decode("false"), do: false
  def decode("true"), do: true
  def decode(:asn1_NOVALUE), do: :asn1_NOVALUE
  def decode(atom) when is_atom(atom), do: Atom.to_string(atom)
  def decode(<<len, str::binary>>) when len == byte_size(str), do: str

  def decode(bin) when is_binary(bin) do
    case :asn1rt_nif.decode_ber_tlv(bin) do
      {{6, oid}, _x} -> @oids[oid]
      {{12, str}, _x} -> str
      {{19, str}, _x} -> str
      _ -> String.trim(bin)
    end
  end

  # Decode Tuples
  # See https://github.com/voltone/x509/blob/v0.8.2/lib/x509/rdn_sequence.ex#L280
  def decode({:AttributeTypeAndValue, oid, val}), do: {oid_name(oid), decode(val)}
  def decode({:OTPSubjectPublicKeyInfo, algo, key}), do: {decode(algo), key}
  def decode({:SignatureAlgorithm, oid, val}), do: {:SignatureAlgorithm, oid_name(oid), val}
  def decode({:Validity, start, stop}), do: {:Validity, decode(start), decode(stop)}
  def decode({:rdnSequence, list}), do: List.flatten(list) |> Enum.map(fn x -> decode(x) end)

  def decode({:PublicKeyAlgorithm, oid, _x}), do: oid_name(oid)
  def decode({:Extension, oid, critical, value}), do: decode_ext(@oids[oid], critical, value)
  def decode({:AccessDescription, oid, uri}), do: {oid_name(oid), decode(uri)}
  def decode({:DistributionPoint, name, _reason, _issuer}), do: decode(name)
  # def decode({:PolicyInformation, oid, value}), do: {oid_name(oid), decode(value)}
  def decode({:PolicyQualifierInfo, oid, octets}), do: {oid_name(oid), octets}

  # fullName = GeneralNames
  # `-> https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L128
  # TODO: otherName, x400Address, directoryName, ediPartyName, iPAddress, registeredID
  def decode({:fullName, value}), do: for({k, v} <- value, do: decode({k, v}))
  def decode({:rfc822Name, list}), do: List.to_string(list)
  def decode({:dNSName, list}), do: List.to_string(list)

  # Decode String Values
  def decode({:utf8String, str}), do: str
  def decode({:printableString, list}), do: List.to_string(list)
  def decode({:ia5String, list}), do: List.to_string(list)
  def decode({:teletexString, list}), do: List.to_string(list)
  def decode({:uniformResourceIdentifier, list}), do: List.to_string(list)

  # catch all for a single value
  def decode(value) when is_list(value), do: List.to_string(value)

  # Decode Time for Internet X.509 PKI Certificate and CRL Profile
  # `-> https://tools.ietf.org/html/rfc5280#section-4.1.2.5
  # UTCTime values for X509 ->   YYMMDDHHMMSSZ  nb: YY >= 50: 19YY, else 20YY
  # GenTime values for X509 -> YYYYMMDDHHMMSSZ
  def decode({:utcTime, [y3, y4, m1, m2, d1, d2, h1, h2, min1, min2, s1, s2, ?Z]}) do
    {y1, y2} = if (y3 - ?0) * 10 + (y4 - ?0) < 50, do: {?2, ?0}, else: {?1, ?9}

    decode({:generalTime, [y1, y2, y3, y4, m1, m2, d1, d2, h1, h2, min1, min2, s1, s2, ?Z]})
  end

  def decode({:generalTime, [y1, y2, y3, y4, m1, m2, d1, d2, h1, h2, min1, min2, s1, s2, ?Z]}) do
    <<y1, y2, y3, y4, ?-, m1, m2, ?-, d1, d2, ?T, h1, h2, ?:, min1, min2, ?:, s1, s2, ?Z>>
  end

  def decode({:utcTime, val}), do: to_string(val) <> " ?"
  def decode({:generalTime, val}), do: to_string(val) <> " ?"

  def decode(:uniformResourceIdentifier, list), do: List.to_string(list)
  # Decode Extensions (some of them anyway)
  # https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L124
  def decode_ext(:"id-ce-subjectAltName", _critical, value) do
    altnames = for {_dNSName, v} <- value, do: to_string(v)
    {:subjectAltName, altnames}
  end

  # https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L225
  def decode_ext(:"id-ce-extKeyUsage", _critical, value) do
    usage = Enum.map(value, fn oid -> oid_name(oid) end)
    {:extKeyUsage, usage}
  end

  # https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L28
  def decode_ext(:"id-ce-authorityKeyIdentifier", critical, value) do
    [atom | rest] = Tuple.to_list(value)
    {atom, [critical | rest]}
  end

  # https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L259
  def decode_ext(:"id-pe-authorityInfoAccess", _critical, value) do
    list = for accessdesc <- value, do: decode(accessdesc)
    {:authorityInfoAccess, list}
  end

  # https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L199
  def decode_ext(:"id-ce-cRLDistributionPoints", _criticial, list) do
    # not sure if r(eason) and c(rlIssuer) are ever not asn1_NOVALUE
    distripoints = for {:DistributionPoint, dp, r, c} <- list, do: {decode(dp), r, c}
    {:cRLDistributionPoints, distripoints}
  end

  # https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Implicit88.asn1#L71
  def decode_ext(:"id-ce-certificatePolicies", _ciritical, value) do
    policies =
      value
      |> Enum.map(fn {:PolicyInformation, oid, val} -> {oid_name(oid), val} end)
      |> Enum.map(fn {name, val} ->
        {name, Enum.map(List.wrap(val), fn x -> decode(x) end)}
      end)

    {:certificatePolicies, policies}
  end

  # raw collection of non-decoded extensions
  def decode_ext(atom, _critical, value) when is_atom(atom) do
    atom = String.split("#{atom}", "-") |> List.last() |> String.to_atom()
    {atom, value}
  end
end
