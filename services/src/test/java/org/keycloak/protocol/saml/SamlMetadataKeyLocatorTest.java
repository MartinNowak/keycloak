/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.protocol.saml;

import java.security.Key;
import java.security.KeyManagementException;
import java.security.cert.X509Certificate;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.keycloak.common.util.Time;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.PublicKeysWrapper;
import org.keycloak.keys.PublicKeyLoader;
import org.keycloak.keys.PublicKeyStorageProvider;
import org.keycloak.rotation.KeyLocator;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.processing.core.util.XMLSignatureUtil;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author rmartinc
 */
public class SamlMetadataKeyLocatorTest {

    private static final String EXPIRED_CERT = "MIIDQTCCAimgAwIBAgIUT8qwq3DECizGLB2tQAaaNSGAVLgwDQYJKoZIhvcNAQELBQAwMDEuMCwGA1UEAwwlaHR0cDovL2xvY2FsaG9zdDo4MDgwL3NhbGVzLXBvc3Qtc2lnLzAeFw0yMzAxMjcxNjAwMDBaFw0yMzAxMjgxNjAwMDBaMDAxLjAsBgNVBAMMJWh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9zYWxlcy1wb3N0LXNpZy8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdIwQZjDffQJL75c/QqqgXPZR7NTFkCGQu/kL3eF/kU8bD1Ck+aKakZyw3xELLgMNg4atu4kt3waSgEKSanvFOpAzH+etS/MMIBYBRKfGcFWAKyr0pukjmx1pw4d3SgQj2lB1FDvVGP62Kl4i34XLxLXtuSkYFiNCTfF26wxfwT0tHTiSynQL2jaa9f5TRAKsXwepUII72Awkk04Zqi3trf5BpNac2s+C6Ey4eAnouWzI5Rg0VDDmt3GzxXPaY6wga9afUSb9z4oJwyW1MiE6ENjfNbdmsUvdXCriRNDviO71CnWrLJA44maKDosubfUtC9Ac9BaRjutFyn1UExE9xAgMBAAGjUzBRMB0GA1UdDgQWBBR4R5i1kWMxzzdQ3TdgI/MuNLChSDAfBgNVHSMEGDAWgBR4R5i1kWMxzzdQ3TdgI/MuNLChSDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAacI/f9YFVTUCGXfh/FCVBQI20bgOs9D6IpIhN8L5kEnY6Ox5t00b9G5Bz64alK3WMR3DdhTEpufX8IMFpMlme/JnnOQXkfmIvzbev4iIKxcKFvS8qNXav8PVxwDApuzgxEq/XZCtFXhDS3q1jGRmlOr+MtQdCNQuJmxy7kOoFPY+UYjhSXTZVrCyFI0LYJQfcZ69bYXd+5h1U3UsN4ZvsBgnrz/IhhadaCtTZVtvyr/uzHiJpqT99VO9/7lwh2zL8ihPyOUVDjdYxYyCi+BHLRB+udnVAfo7t3fbxMi1gV9xVcYaqTJgSArsYM8mxv8p5mhTa8TJknzs4V3Dm+PHs";

    // A valid (long-lived) end-entity certificate used as the first of two signing certs in one KeyDescriptor.
    private static final String LEAF1 = "MIIC6TCCAdGgAwIBAgIUHhpkokRlOm55OaUP3c7ECVu50jUwDQYJKoZIhvcNAQELBQAwFTETMBEGA1UEAwwKaWRwLWxlYWYtMTAgFw0yNjExMTMwOTE3MzlaGA8yMTI2MTAyMDA5MTczOVowFTETMBEGA1UEAwwKaWRwLWxlYWYtMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMOnQZNs8B2I/05kz03yIidnHfyO3sM62RftkRYOBcoo+MKuREDKvHwbRr7x+w62AdkBlY3tIymGEPFU84ca+SLuGSPpcRlDovRQYEajGO5rnJ93nSFKvREs4O8CzX3PllU3WHAvvYXFN+BhuZa16f1dLeoNVdG0IcCmctlytO0RS80DXtrIV/f/SPkZYQbUiA4CJI7qz534YzTCeAKRGAoCWq9cCvjoES4HFyMLHvqkekQoR7/T/Rbomlm9RBDGDiErkso1H9AReNJGlYrFwPvMLOb7qoVnlKM9o8/2fyEmzF5sSHlx0wLnr323udrvvbytO+5bb7JuejckDuoJHisCAwEAAaMvMC0wHQYDVR0OBBYEFKOhF1cy99pR1OebwN25vw/3hAV5MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAJkFi7O6+GrV+sCK19AVlEecLD4a0CCYioEU44J3eAzK7GCXnKD16MMR9T7FutG88YCGDqM8gmlEEtv35q/bauTGCuGsdY2sLYs1MEYErXJOXm89fY4LiqjRls3eTO50KPp+mFLNPWJA5A4J98ga//TyFAfVLBxAFIBevn7hLZ5E/mQ8mzULnR7yIlXpQH/Xe31+LAQ3S16ZaJqfzJyWaM4i/qvbG4jPKzyCR8+XNRjD4yZwLa1pkBw4sFy367uAFRnMgaC/JtVs7HRR89UUh6/3eHJKwzaCKcsyNWkS8lqT+/7FJgEXbtvKzkuZCMYYvhYBJgEzGUeREXyueyOaKCA=";

    // A second valid end-entity certificate, used to reproduce the reported bug where an IdP
    // publishes several signing certs inside a single KeyDescriptor.
    private static final String LEAF2 = "MIIC6TCCAdGgAwIBAgIUB6TVwof3k+pXkMuuX1NuXLYisgMwDQYJKoZIhvcNAQELBQAwFTETMBEGA1UEAwwKaWRwLWxlYWYtMjAgFw0yNjExMTMwOTE3MzlaGA8yMTI2MTAyMDA5MTczOVowFTETMBEGA1UEAwwKaWRwLWxlYWYtMjCCASIwDQYJKoZIhvcNAQELBQADggEPADCCAQoCggEBAK19eS5ZenT+g/ZygeMwbY8RXFVlzq+QnjyynhBa+hkI5CkxzRz9Ld4B98LSk7kHWQ9LqOSzfxG8PsZud4RH4Y77DK/zOhrlz79lhUUt04Fiu0B8UcxHa0QJpphXTltyYZu5O8lw3vUZS5vwD2+p8uKhvdV63z3El9SmO+QVujfWSDUo67nGRqX4KdXE6tVk75PiQYljxDWOZp/vyj+nGAWxi4t8e1iIICS1RluWKf5UYCoCbVn327wIFz4D+aSJu+nxxh5+9+Bb+3WEJPl6FALSBAVfnxZF/w0+2k+b+qmTIrt0OMKYSER8stpw/JXcyRGZY1avkL2loe7moZ1CxwUCAwEAAaMvMC0wHQYDVR0OBBYEFMIWGCXuKkPpnfgSR9dOYqYQGCqqMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAGVkma/AuaEo6sShywCi9QyA3pSIC0MzYw6Q05Je2wjyI6q6PwHd/rKTbnFkmGYAlw52tlsvyb6iiRHJpyd0dsnH7oZDKVw/jg5ZV0i0UNaf5aQy+wGEHEhlLgLP9jJkeuahk5Br8RhTymKI9/UzJK7drKbWuNYAZe49UYEQP8z+CV7WX5CKFA6g745pUnVo871RsjJMh18HHPmImbsrYenLUt66zM8fm41N7ycXT+30gwZCuggTkk/3WuEFm0KzfD4GnD7WMpfNmCNeb9Wot50snUI6LDX1Dg4a9DjH9i3j/wO8bZkoFGw+wdlXGUOPg2UpS6v5JIwNGpxMKYCKGUY=";

    // A valid (long-lived) CA certificate (basicConstraints CA=TRUE), used to verify chain material
    // published inside a KeyDescriptor is never loaded as an IdP signing key.
    private static final String CA_CERT = "MIIC5jCCAc6gAwIBAgIULj3enuaL0ypgrS367ROk9ZcM/+owDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHdGVzdC1jYTAgFw0yNjExMTMwOTE2MTBaGA8yMTI2MTAyMDA5MTYxMFowEjEQMA4GA1UEAwwHdGVzdC1jYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKV6WIlwNPF4yfDSlX30aNcXgajQhGqle68RlZR4cvhW17OhupzYz5szONUNQB4RogS1ZftfCYbU4u5CC6rGBGqmN/LK0VFT3DIQz6ErMhE/68Ynuy8H+SCzGtCSuCr54OUOTXKJOOhqOGOAQtfiAsx5wjAENJVM7G87+8hgIL+whHww1wbfxJcwKx7Ce+Xpj8KfVSpyHRcinK7EjlFbDQjDFJj7jI2zdgJ5uonyqfuXP1q2WrjYbVweMaYQFmfvs6UBQ2q3s0C6yzjuCtctpT9qCz0I2fQpKh4dVONR1lK0FYP/ZIzY+Y/3Lp6xWaIY+S13kDQqGxgkqk5g+7TXFtMCAwEAAaMyMDAwHQYDVR0OBBYEFIJN7kJFX4LvTO3VzOhRy9xHme+lMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBACuFXzV+B7IVTIDBYhfA+RJL7dKXF0pXrurZg9EqSoiW65NWGz9a5lmVw64C9sUyOZsnpQPer7yvqJMVlo4kE2mXKcTMuZHZnnIjh47dK7yPSUTbinI9il5NiWoBSW2T/c1lqQUTHoZE4hVr15U2UIiBVLaUmVpeiOgVPbkm8fLysH95rjSy7Ea/Tj45b3mrEtBSsAhpZlJa6mDGHVB6f7Dg/3AXzf4Gz5d0IFkt7UxyUBEhZl0HxltNXzS0TZYQIeiq+WPLB8+fOQMWPR5PdCVo5AaYwvTed8E1qTNqkVx8vzYKkESUSps1Sc4b1YchZ1oZYM5pc0xa50a8p6c5+1U=";

    // A second valid CA certificate (CA=TRUE), used to check a bundle of only-CA certs is kept whole.
    private static final String CA2_CERT = "MIIC+DCCAeCgAwIBAgIUEyqQ0PyINy55KFTC0hzNKwRIuDIwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEAwwQdGVzdC1jYS1yb2xsb3ZlcjAgFw0yNjExMTMwOTU5NDZaGA8yMTI2MTAyMDA5NTk0NlowGzEZMBcGA1UEAwwQdGVzdC1jYS1yb2xsb3ZlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJpTA0HqjTge/lyvfaougz4jBvM9PmWt21bC2pTIhnjRZPF1B6MNNYeE4ovEyUmiFWJU6iDsZH1vOHhV0/FBEaXUXw35moatgFoIZUYIO1HY1N5acO6HzMZ98KzWRgD9QONtSnm0mB7im2sacZqPF9cWEGJh/Vm2UDHyiFyNdLMxlYRNyBH/jdgQnRorUg6SLVelFA0EPBW+QSOvahjFWzARqwMqaU+1DDdwwot1oSvJPOxu+SNrBLOUo3BrnRwNiHoZqUt8EWdAUEZsrYXV3vrvr3SWeXIDygfE0mfPgKgJjOhW+o9RJvm3IDBJGNH5WIZCHXFkr+Q8btn/nRLQBTcCAwEAAaMyMDAwHQYDVR0OBBYEFP0ERjhyx+17vlJyADPKJF2YlFIlMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABDmBw/XZIxsrU+em4blVeAQ2+C+coJiJaJoP9qBA8DtxqRjrwDbjD/OfXmfNHPFihgPOswY4WHrUB+AbFRVbHtQEftS0cSep2PnIIwaEbc73iRMPJUfdJ/XXjL2HSAsm2JJkYIpBi2xorVyThnKFx0TPj//bmLVrBsujeqZdr7GY5hwv+eCf7qQUmtUylARBxojhVQhz8m/qAqx7HzxZTTSpxJmmrbRWIom3P+MCl7mBhp2iN/FGVy1s/AVz3nQgSF+fgJ9E/LREDciYrez3ce9vQ2zUPOI4esQj7+bo1QnYehdhkCRGmcVVbRsrXIaVWLOm2Rk0iAhh5RXRf9/H5Q=";

    // Builds a minimal IDP descriptor whose single KeyDescriptor contains the given certs.
    private static String idpDescriptorWithKeyDescriptor(String use, String... certificates) {
        StringBuilder certs = new StringBuilder();
        for (String cert : certificates) {
            certs.append("<ds:X509Certificate>").append(cert).append("</ds:X509Certificate>");
        }
        String useAttribute = use == null ? "" : " use=\"" + use + "\"";
        return "<md:EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"http://localhost:8080/realms/keycloak\">"
                + "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
                + "<md:KeyDescriptor" + useAttribute + ">"
                + "<ds:KeyInfo><ds:X509Data>" + certs + "</ds:X509Data></ds:KeyInfo>"
                + "</md:KeyDescriptor>"
                + "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/realms/keycloak/protocol/saml\"></md:SingleSignOnService>"
                + "</md:IDPSSODescriptor>"
                + "</md:EntityDescriptor>";
    }

    private static final String DESCRIPTOR
            = "<md:EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"http://localhost:8080/realms/keycloak\" cacheDuration=\"P1D\">"
            + "<md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
            + "<md:KeyDescriptor use=\"signing\">"
            + "<ds:KeyInfo>"
            + "<ds:KeyName>keycloak</ds:KeyName>"
            + "<ds:X509Data>"
            + "<ds:X509Certificate>MIICyzCCAbOgAwIBAgIILXNek+GBwlgwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAxMIa2V5Y2xvYWswIBcNMjMxMTIzMTU0NTUxWhgPMjA1MTA0MTAxNTQ1NTFaMBMxETAPBgNVBAMTCGtleWNsb2FrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwQVrjErn551TZPkHindw0UzfpkGlj6Isy2WgzRwdjzE4GT26xQYJqG0M1Qt1KN1AUQOyRLhgW2aLn3dYa6fjBnyFiOHCwTUyd/HZPrXFYv81yMQ99vfAoZctjUcFhzKyuDdkWWnqkblEg/viQ/aXP2Gv0Glhx9TE/cxYfAqX5ecfklAz1CTlfh3BpF41fZZglE3k14h4fYWsBqdRIOaFDjcnCp6uePFEOXRew8a5itIP9SJHEwDsSPtjjkOX/kpr98AYmculBa/bxlCEJd8hm4hD272OdoCBsjj5v1DrQ4FL4plD0F0r9VmcWIISWV4cY49cIt2jj08daKAs6b5mEwIDAQABoyEwHzAdBgNVHQ4EFgQUj2pqC0EoVS6al/4sqg+bST3deWwwDQYJKoZIhvcNAQELBQADggEBAL25DtFsext/fhIh6GiSlo+sCBKXj1FKd6hoHGFTi7vcQpk8+8JVVhSCUgE9IxgyuLGZqDplR+x5Vr+i/kVoWTT0/esCF58K1uEp4mOd1Rt92K7IJCXnAhXMB8Atm85sxkiAl8uy5JkGyGek4mdQRomm+m4Xb7o+PgLtrQpFOKACc4CbaAcR1gixhZ06Z8Y5gG/s7l/LaU8YJ1ijtj55buS7KOe/j30GMV+So6HDx59e6jblEZewA10GmcwWO8fy/gI4odUWTG/0rwpZij9NeLwWI2lBjvUxP+inhbemCMob8J/cEndkTUjaeQsC8Dck72jkQa7LdkgFQe4B9nxnz+8=</ds:X509Certificate>"
            + "</ds:X509Data>"
            + "</ds:KeyInfo>"
            + "</md:KeyDescriptor>"
            + "<md:KeyDescriptor use=\"signing\">"
            + "<ds:KeyInfo>"
            + "<ds:KeyName>keycloak2</ds:KeyName>"
            + "<ds:X509Data>"
            + "<ds:X509Certificate>MIICzjCCAbagAwIBAgIJAIGXzrijFn9HMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMTCWtleWNsb2FrMjAgFw0yMzExMjMxNjI3MDNaGA8yMDUxMDQxMDE2MjcwM1owFDESMBAGA1UEAxMJa2V5Y2xvYWsyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs53pde5xBfaXZHVWahcdGjwfZxHDmdh/EeF0GsSPU8z36+1R9T/xVJpP6xZgmNpqh09EHSBYRXRsPh1EsJ/cCLtGYWt0HMYRCSBVkwBQQq+xwjuTrLNllroc1QBOOUbe0V3cLbKVZLebdsD+K/hNz/K3lZB6BIb82y6GoiEcAZ57+EwUg0dfRPphMEHDPuggp0gWT5TPm47U6TeE3MKk6WzMgTZjLkHuuqOksBwTIT3y5Q5RFGsydnv5szlfWp8UEQjN6tHAZNlyDYqL9r/CuWmGolkd09JoFfXnbpLNiMciDcBpxZi1RhZijVXx9pg4xdU6J76wYfL2vLuYjhQqlwIDAQABoyEwHzAdBgNVHQ4EFgQUWHGU4mBOKQ/1kI9OhLVJdozBnkYwDQYJKoZIhvcNAQELBQADggEBAJV/5MVxAIh8nfpnNmyNNSosF5bauda74+z5SWyPZlvLBf3GdsG+MQQ0ApE+ZjtMH1X2E8t1dfCdwVv94rbBiDUS+hRIqFkgQgq6y/1+IEagi6epBT/mmebW0oM034gFu5+XzmH+U3F/ifjVWV61CmMAWfpn7poioesWSucOq+TwHtVBOCazly+fZVJgmJd6IZ8rqLiso8Bd6OS0tyU5/lFZ3iz1CQB9WQV+X0sF68KVcIJBw/mQ2HMN3G21M4Xa1ZZggzV70JpsMaaHPmJjCZ8OhbqTthZCY3dLJgy+96WMGq8zuhbULs5GNA8mt52GAq1Kw6r/bYFG+PEqYQNxPDM=</ds:X509Certificate>"
            + "</ds:X509Data>"
            + "</ds:KeyInfo>"
            + "</md:KeyDescriptor>"
            + "<md:ArtifactResolutionService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"http://localhost:8080/realms/keycloak/protocol/saml/resolve\" index=\"0\"></md:ArtifactResolutionService>"
            + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/realms/keycloak/protocol/saml\"></md:SingleLogoutService>"
            + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/realms/keycloak/protocol/saml\"></md:SingleLogoutService>"
            + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8080/realms/keycloak/protocol/saml\"></md:SingleLogoutService>"
            + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"http://localhost:8080/realms/keycloak/protocol/saml\"></md:SingleLogoutService>"
            + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>"
            + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>"
            + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>"
            + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
            + "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/realms/keycloak/protocol/saml\"></md:SingleSignOnService>"
            + "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/realms/keycloak/protocol/saml\"></md:SingleSignOnService>"
            + "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"http://localhost:8080/realms/keycloak/protocol/saml\"></md:SingleSignOnService>"
            + "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8080/realms/keycloak/protocol/saml\"></md:SingleSignOnService>"
            + "</md:IDPSSODescriptor>"
            + "</md:EntityDescriptor>";

    // test PublicKeyStorageProvider that just loads the keys in every call
    private static class TestPublicKeyStorageProvider implements PublicKeyStorageProvider {

        private PublicKeysWrapper load(PublicKeyLoader loader) {
            try {
                return loader.loadKeys();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public KeyWrapper getPublicKey(String modelKey, String kid, String algorithm, PublicKeyLoader loader) {
            return load(loader).getKeyByKidAndAlg(kid, algorithm);
        }

        @Override
        public KeyWrapper getFirstPublicKey(String modelKey, String algorithm, PublicKeyLoader loader) {
            return getFirstPublicKey(modelKey, k -> algorithm.equals(k.getAlgorithm()), loader);
        }

        @Override
        public KeyWrapper getFirstPublicKey(String modelKey, Predicate<KeyWrapper> predicate, PublicKeyLoader loader) {
            return load(loader).getKeyByPredicate(predicate);
        }

        @Override
        public List<KeyWrapper> getKeys(String modelKey, PublicKeyLoader loader) {
            return load(loader).getKeys();
        }

        @Override
        public boolean reloadKeys(String modelKey, PublicKeyLoader loader) {
            return false;
        }

        @Override
        public void close() {
            // no-op
        }
    }

    // PublicKeyLoader from the metadata descriptor string
    private static class TestSamlMetadataPublicKeyLoader extends SamlAbstractMetadataPublicKeyLoader {

        private final String descriptor;

        public TestSamlMetadataPublicKeyLoader(String descriptor, boolean forIdP) {
            super(forIdP);
            this.descriptor = descriptor;
        }

        @Override
        protected String getKeys() throws Exception {
            return descriptor;
        }
    }

    @Test
    public void testCertificatesSign() throws KeyManagementException {
        PublicKeyStorageProvider keyStorage = new  TestPublicKeyStorageProvider();
        PublicKeyLoader loader = new TestSamlMetadataPublicKeyLoader(DESCRIPTOR, true);

        KeyLocator keyLocator = new SamlMetadataKeyLocator("test", loader, KeyUse.SIG, keyStorage);

        Key keycloak = keyLocator.getKey("keycloak");
        Assert.assertNotNull(keycloak);
        Assert.assertEquals(keycloak, keyLocator.getKey(keycloak));

        Key keycloak2 = keyLocator.getKey("keycloak2");
        Assert.assertNotNull(keycloak2);
        Assert.assertEquals(keycloak2, keyLocator.getKey(keycloak2));

        MatcherAssert.assertThat(StreamSupport.stream(keyLocator.spliterator(), false).collect(Collectors.toList()),
                Matchers.containsInAnyOrder(keycloak, keycloak2));

        keyLocator = new SamlMetadataKeyLocator("test", loader, KeyUse.ENC, keyStorage);

        Assert.assertNull(keyLocator.getKey("keycloak"));
        Assert.assertNull(keyLocator.getKey(keycloak));

        Assert.assertNull(keyLocator.getKey("keycloak2"));
        Assert.assertNull(keyLocator.getKey(keycloak2));

        Assert.assertFalse(keyLocator.iterator().hasNext());
    }

    @Test
    public void testCertificatesUseNull() throws KeyManagementException {
        PublicKeyStorageProvider keyStorage = new  TestPublicKeyStorageProvider();
        // both certificates are use null
        String desc = DESCRIPTOR.replaceAll("<md:KeyDescriptor use=\"signing\">", "<md:KeyDescriptor>");
        PublicKeyLoader loader = new TestSamlMetadataPublicKeyLoader(desc, true);
        KeyLocator keyLocator = new SamlMetadataKeyLocator("test", loader, KeyUse.SIG, keyStorage);

        Key keycloak = keyLocator.getKey("keycloak");
        Assert.assertNotNull(keycloak);
        Assert.assertEquals(keycloak, keyLocator.getKey(keycloak));

        Key keycloak2 = keyLocator.getKey("keycloak2");
        Assert.assertNotNull(keycloak2);
        Assert.assertEquals(keycloak2, keyLocator.getKey(keycloak2));

        MatcherAssert.assertThat(StreamSupport.stream(keyLocator.spliterator(), false).collect(Collectors.toList()),
                Matchers.containsInAnyOrder(keycloak, keycloak2));

        keyLocator = new SamlMetadataKeyLocator("test", loader, KeyUse.ENC, keyStorage);

        keycloak = keyLocator.getKey("keycloak");
        Assert.assertNotNull(keycloak);
        Assert.assertEquals(keycloak, keyLocator.getKey(keycloak));

        keycloak2 = keyLocator.getKey("keycloak2");
        Assert.assertNotNull(keycloak2);
        Assert.assertEquals(keycloak2, keyLocator.getKey(keycloak2));

        MatcherAssert.assertThat(StreamSupport.stream(keyLocator.spliterator(), false).collect(Collectors.toList()),
                Matchers.containsInAnyOrder(keycloak, keycloak2));
    }

    @Test
    public void testCertificatesExpired() throws KeyManagementException, ProcessingException {
        PublicKeyStorageProvider keyStorage = new  TestPublicKeyStorageProvider();
        // first certificate keycloak is changed to the expired one
        String desc = DESCRIPTOR.replaceFirst("<ds:X509Certificate>[^<]+</ds:X509Certificate>", "<ds:X509Certificate>" + EXPIRED_CERT +"</ds:X509Certificate>");
        PublicKeyLoader loader = new TestSamlMetadataPublicKeyLoader(desc, true);

        KeyLocator keyLocator = new SamlMetadataKeyLocator("test", loader, KeyUse.SIG, keyStorage);

        Key keycloak = keyLocator.getKey("keycloak");
        Assert.assertNull(keycloak);
        X509Certificate keycloakExp = XMLSignatureUtil.getX509CertificateFromKeyInfoString(EXPIRED_CERT);
        Assert.assertNull(keyLocator.getKey(keycloakExp.getPublicKey()));

        Key keycloak2 = keyLocator.getKey("keycloak2");
        Assert.assertNotNull(keycloak2);
        Assert.assertEquals(keycloak2, keyLocator.getKey(keycloak2));

        MatcherAssert.assertThat(StreamSupport.stream(keyLocator.spliterator(), false).collect(Collectors.toList()),
                Matchers.containsInAnyOrder(keycloak2));
    }

    @Test
    public void testLoaderWithExpiration() throws Exception {
        Long expiration = Time.currentTimeMillis() + (24 * 60 * 60 * 1000);
        GregorianCalendar cal = new GregorianCalendar();
        cal.setTimeInMillis(expiration);
        XMLGregorianCalendar calendar = DatatypeFactory.newInstance().newXMLGregorianCalendar(cal);

        // check expiration is read OK using cacheDuration which is in the default descriptor, 5s window
        PublicKeyLoader loader = new TestSamlMetadataPublicKeyLoader(DESCRIPTOR, true);
        MatcherAssert.assertThat(loader.loadKeys().getExpirationTime(), Matchers.allOf(Matchers.greaterThanOrEqualTo(expiration), Matchers.lessThan(expiration + 5000)));

        // check expiration is read OK using validUntil instead cacheDuration, 5s window
        String desc = DESCRIPTOR.replaceFirst("cacheDuration=\"P1D\"", "validUntil=\"" + calendar.toXMLFormat() + "\"");
        loader = new TestSamlMetadataPublicKeyLoader(desc, true);
        MatcherAssert.assertThat(loader.loadKeys().getExpirationTime(), Matchers.allOf(Matchers.greaterThan(expiration - 5000), Matchers.lessThanOrEqualTo(expiration)));
    }

    @Test
    public void testMultipleCertificatesInOneSigningKeyDescriptor() throws KeyManagementException, ProcessingException {
        PublicKeyStorageProvider keyStorage = new TestPublicKeyStorageProvider();
        // Issue 47392: an IdP publishing several signing certs in one KeyDescriptor must load them all.
        String desc = idpDescriptorWithKeyDescriptor("signing", LEAF1, LEAF2);
        PublicKeyLoader loader = new TestSamlMetadataPublicKeyLoader(desc, true);
        KeyLocator keyLocator = new SamlMetadataKeyLocator("test", loader, KeyUse.SIG, keyStorage);

        X509Certificate leaf1 = XMLSignatureUtil.getX509CertificateFromKeyInfoString(LEAF1);
        X509Certificate leaf2 = XMLSignatureUtil.getX509CertificateFromKeyInfoString(LEAF2);

        Key key1 = keyLocator.getKey(leaf1.getPublicKey());
        Key key2 = keyLocator.getKey(leaf2.getPublicKey());
        Assert.assertNotNull(key1);
        Assert.assertNotNull(key2);
        MatcherAssert.assertThat(StreamSupport.stream(keyLocator.spliterator(), false).collect(Collectors.toList()),
                Matchers.containsInAnyOrder(key1, key2));

        // signing certs are not visible as encryption keys
        keyLocator = new SamlMetadataKeyLocator("test", loader, KeyUse.ENC, keyStorage);
        Assert.assertFalse(keyLocator.iterator().hasNext());
    }

    @Test
    public void testMultipleCertificatesInOneEncryptionKeyDescriptor() throws KeyManagementException, ProcessingException {
        PublicKeyStorageProvider keyStorage = new TestPublicKeyStorageProvider();
        String desc = idpDescriptorWithKeyDescriptor("encryption", LEAF1, LEAF2);
        PublicKeyLoader loader = new TestSamlMetadataPublicKeyLoader(desc, true);
        KeyLocator keyLocator = new SamlMetadataKeyLocator("test", loader, KeyUse.ENC, keyStorage);

        X509Certificate leaf1 = XMLSignatureUtil.getX509CertificateFromKeyInfoString(LEAF1);
        X509Certificate leaf2 = XMLSignatureUtil.getX509CertificateFromKeyInfoString(LEAF2);

        Key key1 = keyLocator.getKey(leaf1.getPublicKey());
        Key key2 = keyLocator.getKey(leaf2.getPublicKey());
        Assert.assertNotNull(key1);
        Assert.assertNotNull(key2);
        MatcherAssert.assertThat(StreamSupport.stream(keyLocator.spliterator(), false).collect(Collectors.toList()),
                Matchers.containsInAnyOrder(key1, key2));

        // encryption certs are not visible as signing keys
        keyLocator = new SamlMetadataKeyLocator("test", loader, KeyUse.SIG, keyStorage);
        Assert.assertFalse(keyLocator.iterator().hasNext());
    }

    @Test
    public void testCACertificateSkippedInKeyDescriptor() throws KeyManagementException, ProcessingException {
        PublicKeyStorageProvider keyStorage = new TestPublicKeyStorageProvider();
        // A signing descriptor bundling a leaf plus its CA: only the leaf loads (CA cert is unexpired).
        String desc = idpDescriptorWithKeyDescriptor("signing", LEAF1, CA_CERT);
        PublicKeyLoader loader = new TestSamlMetadataPublicKeyLoader(desc, true);
        KeyLocator keyLocator = new SamlMetadataKeyLocator("test", loader, KeyUse.SIG, keyStorage);

        X509Certificate leaf1 = XMLSignatureUtil.getX509CertificateFromKeyInfoString(LEAF1);
        X509Certificate ca = XMLSignatureUtil.getX509CertificateFromKeyInfoString(CA_CERT);

        Key key1 = keyLocator.getKey(leaf1.getPublicKey());
        Assert.assertNotNull(key1);
        Assert.assertNull(keyLocator.getKey(ca.getPublicKey()));
        MatcherAssert.assertThat(StreamSupport.stream(keyLocator.spliterator(), false).collect(Collectors.toList()),
                Matchers.contains(key1));
    }

    @Test
    public void testSingleSelfSignedCACertificateIsKept() throws KeyManagementException, ProcessingException {
        PublicKeyStorageProvider keyStorage = new TestPublicKeyStorageProvider();
        // A lone self-signed leaf is commonly CA=TRUE (openssl req -x509); it must not be stripped.
        String desc = idpDescriptorWithKeyDescriptor("signing", CA_CERT);
        PublicKeyLoader loader = new TestSamlMetadataPublicKeyLoader(desc, true);
        KeyLocator keyLocator = new SamlMetadataKeyLocator("test", loader, KeyUse.SIG, keyStorage);

        X509Certificate ca = XMLSignatureUtil.getX509CertificateFromKeyInfoString(CA_CERT);
        Assert.assertNotNull(keyLocator.getKey(ca.getPublicKey()));
        MatcherAssert.assertThat(StreamSupport.stream(keyLocator.spliterator(), false).collect(Collectors.toList()),
                Matchers.contains(keyLocator.getKey(ca.getPublicKey())));
    }

    @Test
    public void testAllCACertificatesInOneKeyDescriptorAreKept() throws KeyManagementException, ProcessingException {
        PublicKeyStorageProvider keyStorage = new TestPublicKeyStorageProvider();
        // All-CA bundle is indistinguishable from self-signed rollover keys, so keep them all.
        String desc = idpDescriptorWithKeyDescriptor("signing", CA_CERT, CA2_CERT);
        PublicKeyLoader loader = new TestSamlMetadataPublicKeyLoader(desc, true);
        KeyLocator keyLocator = new SamlMetadataKeyLocator("test", loader, KeyUse.SIG, keyStorage);

        X509Certificate ca = XMLSignatureUtil.getX509CertificateFromKeyInfoString(CA_CERT);
        X509Certificate ca2 = XMLSignatureUtil.getX509CertificateFromKeyInfoString(CA2_CERT);

        Key key1 = keyLocator.getKey(ca.getPublicKey());
        Key key2 = keyLocator.getKey(ca2.getPublicKey());
        Assert.assertNotNull(key1);
        Assert.assertNotNull(key2);
        MatcherAssert.assertThat(StreamSupport.stream(keyLocator.spliterator(), false).collect(Collectors.toList()),
                Matchers.containsInAnyOrder(key1, key2));
    }
}
