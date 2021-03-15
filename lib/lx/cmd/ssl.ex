defmodule Lx.Cmd.Ssl do
  @moduledoc """
  Simple ssl certificate chain checker

  From [Erlang's OTP-PKIX.asn1](https://github.com/erlang/otp/blob/master/lib/public_key/asn1/OTP-PKIX.asn1)

  ```asn1
  OTPCertificate  ::=  SEQUENCE  {
       tbsCertificate       OTPTBSCertificate,
       signatureAlgorithm   SignatureAlgorithm,
       signature            BIT STRING
  }
  ```

  where the OTPTBSCertificate object is defined as:

  ```asn1
  OTPTBSCertificate  ::=  SEQUENCE  {
       version         [0]  Version DEFAULT v1,
       serialNumber         CertificateSerialNumber,
       signature            SignatureAlgorithm,
       issuer               Name,
       validity             Validity,
       subject              Name,
       subjectPublicKeyInfo OTPSubjectPublicKeyInfo,
       issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
       subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
       extensions      [3]  Extensions OPTIONAL                 -- If present, version MUST be v3
  }
  ```

  Where the issuer & subject are DN's (distinguished names) which consists of a sequence
  of "Relative Distinguised Names" (the attr=value parts). e.g.
  "CN=Jeff Smith,OU=Sales,DC=Fabrikam,DC=COM"

  From [PKIX1Explicit88.asn1](https://github.com/erlang/otp/blob/master/lib/public_key/asn1/PKIX1Explicit88.asn1)

  ```asn1
  Name ::= CHOICE {
        rdnSequence  RDNSequence  -- only one possibility for now
  }

  DistinguishedName          ::= RDNSequence
  RDNSequence                ::= SEQUENCE OF RelativeDistinguishedName
  RelativeDistinguishedName  ::= SET SIZE (1 .. MAX) OF AttributeTypeAndValue

  AttributeTypeAndValue      ::= SEQUENCE {
       type    AttributeType,
       value   AttributeValue
  }
  AttributeType              ::=  OBJECT IDENTIFIER
  AttributeValue             ::=  ANY

  Validity ::= SEQUENCE {notBefore  Time,
                         notAfter   Time
  }

  Time ::= CHOICE {
       utcTime        UTCTime,
       generalTime    GeneralizedTime
  }

  SubjectPublicKeyInfo  ::=  SEQUENCE  {
       algorithm            AlgorithmIdentifier,
       subjectPublicKey     BIT STRING
  }

  AlgorithmIdentifier  ::=  SEQUENCE  {
     algorithm               OBJECT IDENTIFIER,
     parameters              ANY DEFINED BY algorithm OPTIONAL
  } -- contains a value of the type registered for use with the algorithm object identifier value


  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

  Extension  ::=  SEQUENCE  {
       extnID      OBJECT IDENTIFIER,
       critical    BOOLEAN DEFAULT FALSE,  -- true for CA cert?
       extnValue   OCTET STRING
  }
  ```

  Attribute names are also defined in 

  ```asn1
  -- presented in pairs: the AttributeType followed by the
  --   type definition for the corresponding AttributeValue

  --Arc for standard naming attributes
  id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }

  -- Naming attributes of type X520name

  id-at-name              AttributeType ::= { id-at 41 }   --> {2, 5, 4, 41}
  id-at-surname           AttributeType ::= { id-at 4 }    --> {2, 5, 4, 4}
  id-at-givenName         AttributeType ::= { id-at 42 }
  id-at-initials          AttributeType ::= { id-at 43 }
  id-at-generationQualifier AttributeType ::= { id-at 44 }

  id-at-countryName       AttributeType ::= { id-at 6 }  --> {2, 5, 4, 6}
  X520countryName ::=     PrintableString (SIZE (2))
  """

  # See:
  # - https://erlang.org/doc/apps/public_key/public_key_records.html
  # - https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
  #   utcTime -> YYMMDDHHMMSSZ -> YY < 50 -> 19YY, else 20YY (!!)
  # - https://tools.ietf.org/html/rfc5280#section-4.1.2.5.2
  #   generalTime -> YYYYMMDDHHMMSSZ
  #   see also https://github.com/google/certificate-transparency-go/blob/master/asn1/asn1.go#L395

  # 1) /etc/ssl/certs -> 260+ trusted root CA's
  # -----------------------------------------------------------------------
  # c = File.read!("/etc/ssl/certs/Staat_der_Nederlanden_EV_Root_CA.pem")
  # `-> "-----BEGIN CERTIFICATE-----\nMI ... ==\n-----END CERTIFICATE-----\n"
  # [dsaEntry] = :public_key.pem_decode(c)
  # [
  #  {:Certificate,
  #   <<48, 130, 5, 112, 48, 130, 3, 88, 160, 3, 2, 1, 2, 2, 4, 0, 152, 150, 141,
  #     48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 88, 49, 11,
  #     48, 9, 6, 3, 85, 4, 6, 19, 2, ...>>,
  #   :not_encrypted}
  # ]
  #
  # ------------------------------------------------------------------------
  # :public_key.pem_entry_decode(dsaEntry)
  # {:Certificate,
  #
  # {:TBSCertificate, :v3, 10000013,
  #  {:AlgorithmIdentifier, {1, 2, 840, 113549, 1, 1, 11}, <<5, 0>>},
  #  {:rdnSequence,
  #   [
  #     [{:AttributeTypeAndValue, {2, 5, 4, 6}, <<19, 2, 78, 76>>}],
  #     [
  #       {:AttributeTypeAndValue, {2, 5, 4, 10},
  #        <<12, 21, 83, 116, 97, 97, 116, 32, 100, 101, 114, 32, 78, 101, 100, 101, 114, 108, 97, 110, 100, 101, 110>>}
  #     ],
  #     [
  #       {:AttributeTypeAndValue, {2, 5, 4, 3},
  #        "\f Staat der Nederlanden EV Root CA"}
  #     ]
  #   ]},
  #  {:Validity, {:utcTime, '101208111929Z'}, {:utcTime, '221208111028Z'}},
  #  {:rdnSequence,
  #   [
  #     [{:AttributeTypeAndValue, {2, 5, 4, 6}, <<19, 2, 78, 76>>}],
  #     [
  #       {:AttributeTypeAndValue, {2, 5, 4, 10}, <<12, 21, 83, 116, 97, 97, 116, 32, 100, 101, 114, 32, 78, 101, 100, 101, 114, 108, 97, 110, 100, 101, 110>>}
  #     ],
  #     [
  #       {:AttributeTypeAndValue, {2, 5, 4, 3}, "\f Staat der Nederlanden EV Root CA"}
  #     ]
  #   ]},
  #  {:SubjectPublicKeyInfo,
  #   {:AlgorithmIdentifier, {1, 2, 840, 113549, 1, 1, 1}, <<5, 0>>},
  #   <<48, 130, 2, 10, 2, 130, 2, 1, 0, 227, 199, 126, 137, 249, 36, 75, 58, 210,
  #     51, 131, 53, 44, 105, 236, 220, 9, 164, 227, 81, 168, 37, 43, 121, 184, 8,
  #     61, 224, ...>>},
  #  :asn1_NOVALUE,
  #  :asn1_NOVALUE,
  #  [
  #    {:Extension, {2, 5, 29, 19}, true, <<48, 3, 1, 1, 255>>},
  #    {:Extension, {2, 5, 29, 15}, true, <<3, 2, 1, 6>>},
  #    {:Extension, {2, 5, 29, 14}, false,
  #     <<4, 20, 254, 171, 0, 144, 152, 158, 36, 252, 169, 204, 26, 138, 251, 39,
  #       184, 191, 48, 110, 168, 59>>}
  #  ]},
  #
  #  {:AlgorithmIdentifier, {1, 2, 840, 113549, 1, 1, 11}, <<5, 0>>},
  #
  #   <<207, 119, 44, 110, 86, 190, 78, 179, 182, 132, 0, 148, 171, 71, 201, 13, 210,
  #   118, 199, 134, 159, 29, 7, 211, 182, 180, 187, 8, 120, 175, 105, 210, 11, 73,
  #   222, 51, 197, 172, 173, 194, 136, 2, 125, 6, 183, 53, ...>>
  # }
  #
  # ---------------------------------------------------------------------------
  #
  # The pkix_decode_cert recursively tries to parse as much as it can from the
  # certificate.  dsaEntry = {:Certificate, << ... >>, :not_encrypted}, then do:
  #
  # :public_key.pkix_decode_cert(dsaEntry |> elem(1), :otp)
  # {:OTPCertificate,
  #  {:OTPTBSCertificate, :v3, 10000013,
  #   {:SignatureAlgorithm, {1, 2, 840, 113549, 1, 1, 11}, :NULL},
  #   {:rdnSequence,
  #    [
  #      [{:AttributeTypeAndValue, {2, 5, 4, 6}, 'NL'}],
  #      [
  #        {:AttributeTypeAndValue, {2, 5, 4, 10},
  #         {:utf8String, "Staat der Nederlanden"}}
  #      ],
  #      [
  #        {:AttributeTypeAndValue, {2, 5, 4, 3},
  #         {:utf8String, "Staat der Nederlanden EV Root CA"}}
  #      ]
  #    ]},
  #   {:Validity, {:utcTime, '101208111929Z'}, {:utcTime, '221208111028Z'}},
  #   {:rdnSequence,
  #    [
  #      [{:AttributeTypeAndValue, {2, 5, 4, 6}, 'NL'}],
  #      [
  #        {:AttributeTypeAndValue, {2, 5, 4, 10},
  #         {:utf8String, "Staat der Nederlanden"}}
  #      ],
  #      [
  #        {:AttributeTypeAndValue, {2, 5, 4, 3},
  #         {:utf8String, "Staat der Nederlanden EV Root CA"}}
  #      ]
  #    ]},
  #   {:OTPSubjectPublicKeyInfo,
  #    {:PublicKeyAlgorithm, {1, 2, 840, 113549, 1, 1, 1}, :NULL},
  #    {:RSAPublicKey,
  #     92925...,
  #     65537}},
  #   :asn1_NOVALUE,
  #   :asn1_NOVALUE,
  #   [
  #     {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, :asn1_NOVALUE}},
  #     {:Extension, {2, 5, 29, 15}, true, [:keyCertSign, :cRLSign]},
  #     {:Extension, {2, 5, 29, 14}, false,
  #      <<254, 171, 0, 144, 152, 158, 36, 252, 169, 204, 26, 138, 251, 39, 184,
  #        191, 48, 110, 168, 59>>}
  #   ]}, {:SignatureAlgorithm, {1, 2, 840, 113549, 1, 1, 11}, :NULL},
  #  <<207, 119, 44, 110, 86, 190, 78, 179, 182, 132, 0, 148, 171, 71, 201, 13, 210,
  #    118, 199, 134, 159, 29, 7, 211, 182, 180, 187, 8, 120, 175, 105, 210, 11, 73,
  #    222, 51, 197, 172, 173, 194, 136, 2, 125, 6, 183, 53, ...>>}
  #
  # --------------------------------------------------------------------------------
  # Some parts can be der_decoded using the correct oid.  So here oid is {2, 5,
  # 4, 3} which is :X520CommonName (example from the erlang page ...)
  #
  # :public_key.der_decode(:X520CommonName, <<19,8,101,114,108,97,110,103,67,65>>) 
  # {:printableString, 'erlangCA'}
  #
  # Or using https://github.com/BoringButGreat/public_key_utils/blob/master/lib/oid.ex
  # seeing how {2, 5, 4, 6} is oid for :id-at-countryName we do:
  #
  # :public_key.der_decode(:"id-at-countryName", <<19, 2, 78, 76>>) 
  # `-> oops, got an error, undefined asn1 type
  # - hmm, see https://www.obj-sys.com/asn1tutorial/node124.html
  #   <<19 = PrintableString, 2 = length, 78 76 = value (NL)>>
  #
  # Not sure how to go from oid {2, 5, 4, 6} -> :X520CountryName ???
  # The hrl says {2, 5, 4, 6} -> 'id-at-countryName'
  #
  # - https://github.com/yrashk/erlang/blob/master/lib/public_key/asn1/OTP-PUB-KEY.hrl
  #   Line 445 -define('id-at-countryName', {2, 5, 4, 6})
  # - https://github.com/yrashk/erlang/blob/master/lib/public_key/asn1/OTP-PUB-KEY.erl
  #   doesn't do much?
  # - https://github.com/yrashk/erlang/blob/master/lib/public_key/asn1/OTP-PKIX.asn1#L34
  #   `-> see also lines 214-216 which seems to define ID id-at-countryName as TYPE X520countryName
  #
  # :public_key.der_decode(:X520countryName, <<19, 2, 78, 76>>)
  # `-> 'NL'
  # --or--
  # see: https://github.com/voltone/x509/blob/v0.8.2/lib/x509/rdn_sequence.ex#L244
  # :pubkey_cert_records.transform({:AttributeTypeAndValue, {2, 5, 4, 6}, <<19, 2, 78, 76>>}, :decode)
  # `-> {:AttributeTypeAndValue, {2, 5, 4, 6}, 'NL'}
  #
  # As another example:
  #
  # :pubkey_cert_records.transform({:AttributeTypeAndValue, {2, 5, 4, 10}, <<12, 21, 83, 116, 97, 97, 116, 32, 100, 101, 114, 32, 78, 101, 100, 101, 114, 108, 97, 110, 100, 101, 110>>}, :decode)
  # `-> {:AttributeTypeAndValue, {2, 5, 4, 10}, {:utf8String, "Staat der Nederlanden"}}
  #
  #  Note:
  #  - transform/2 takes several constructs it can either :decode/:encode (= the 2dn param)
  #  - rdnSequence, AttributeTypeAndValue, 
  #
  #
  # -----------------------------------------------------------------------------------------
  #
  # - while ID {:"id-at-organizationName", {2, 5, 4, 10}} -> TYPE :X520OrganizationName
  # :public_key.der_decode(:X520OrganizationName, <<12, 21, 83, 116, 97, 97, 116, 32, 100, 101, 114, 32, 78, 101, 100, 101, 114, 108, 97, 110, 100, 101, 110>>)
  # `-> {:utf8String, "Staat der Nederlanden"}
  #
  # see https://github.com/BoringButGreat/public_key_utils/blob/master/lib/certificate.ex#L114
  # `-> uses :asn1rt_nif
  # :asn1rt_nif.decode_ber_tlv(<<12, 21, 83, 116, 97, 97, 116, 32, 100, 101, 114, 32, 78, 101, 100, 101, 114, 108, 97, 110, 100, 101, 110>>)
  # {{12, "Staat der Nederlanden"}, ""}  -> 12 is UTF8String (see https://en.wikipedia.org/wiki/X.690)
  #
  # this uses a nif func to decode ber:
  # see https://github.com/erlang/otp/blob/master/lib/asn1/src/asn1rt_nif.erl#L82      -> decode_der_tlv
  # `-> https://github.com/erlang/otp/blob/master/lib/asn1/c_src/asn1_erl_nif.c#L1257  -> der_decode_tlv_raw
  # `-> https://github.com/erlang/otp/blob/master/lib/asn1/c_src/asn1_erl_nif.c#L839   -> der_decode_begin
  # https://github.com/erlang/otp/blob/master/lib/asn1/src/asn1.app.src#L5
  # `-> only exports asn1rt_nif as the only module of the asn1.app
  #
  # Another example from https://en.wikipedia.org/wiki/ASN.1 (Example encoded in DER)
  # :asn1rt_nif.decode_ber_tlv(<<0x30, 0x13, 0x02, 0x01, 0x05, 0x16, 0x0e, 0x41, 0x6e, 0x79, 0x62, 0x6f, 0x64, 0x79, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x3f>>)
  # {{16, [{2, <<5>>}, {22, "Anybody there?"}]}, ""}
  # `-> https://en.wikipedia.org/wiki/X.690 -> 16 is sequence, 22 is IA5String
  #
  # ----------------------------------------------------------------------------------------
  # https://www.obj-sys.com/asn1tutorial/node124.html -- asn1 types
  #
  require Logger
  alias EasySSL

  # @pubkey_schema Record.extract_all(from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  @oids Lx.Utils.load_oids()

  def run(argv) do
    Logger.info("running with #{inspect(argv)}")
    get_ssl(hd(argv))
    :ok
  end

  defp partial_chain(certs) do
    Logger.info("certificate chain length #{Enum.count(certs)}")
    # cert = hd(certs) |> :public_key.pkix_decode_cert(:otp) |> get_field(:tbsCertificate)

    certs
    |> Enum.reverse()
    |> Enum.map(fn cert -> der_decode(cert) end)
    |> Enum.with_index()
    |> Enum.map(fn {x, idx} ->
      msg =
        "subject=#{x.subjectCommonname}, issuer=#{x.issuerCommonname}" <>
          ", not_before=#{x.not_before}, not_after=#{x.not_after}"

      Logger.info("depth=#{idx}, #{msg}")
    end)

    {:trusted_ca, List.last(certs)}
  end

  @doc """
  get certificate as der encoded binary
  """
  def get_ssl(hostname) do
    Logger.info("hostname: #{inspect(hostname)}")
    host = to_charlist(hostname)
    {:ok, sock} = :gen_tcp.connect(host, 443, active: false)

    {:ok, sock} =
      :ssl.connect(sock,
        versions: [:"tlsv1.1", :"tlsv1.2"],
        ciphers: :ssl.cipher_suites(:default, :"tlsv1.2"),
        server_name_indication: host,
        # verify: :verify_peer,
        # cacertfile: "/etc/ssl/certs/Staat_der_Nederlanden_EV_Root_CA.pem",
        partial_chain: &partial_chain/1,
        depth: 10,
        customize_hostname_check: [
          match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
        ]
      )

    result =
      case :ssl.peercert(sock) do
        {:ok, der} ->
          # Test test_decode
          der_decode(der)
          # /end test.

          EasySSL.parse_der(der)

        error ->
          {:error, error}
      end

    :ssl.close(sock)
    result
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
