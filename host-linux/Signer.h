/*
 * Chrome Token Signing Native Host
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#pragma once

#include "PKCS11CardManager.h"
#include "Labels.h"
#include "PKCS11Path.h"
#include <iostream>
#include <regex>
#include <algorithm>
#include "BaseConverter.h"
#include "rapidmxl.hpp"
#include "rapidxml_print.hpp"
#include <fstream>

#include <QDebug>
#include <QDialog>
#include <QDialogButtonBox>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRegExpValidator>
#include <QSslCertificate>
#include <QSslCertificateExtension>
#include <QTimeLine>
#include <QTextBrowser>
#include <QVBoxLayout>

#include <future>
#include <string>

class Signer: public QDialog {
    enum {
        UserCancel = 0,
        TechnicalError = -1,
        AuthError = -2,
    };
public:
    static QVariantMap sign(const QString &contents, const QString &cert) {
        std::vector<unsigned char> data = fromHex(cert);
        QSslCertificate c(QByteArray::fromRawData((const char*)data.data(), int(data.size())), QSsl::Der);
        bool isNonRepudiation = false;
        for(const QSslCertificateExtension &ex: c.extensions())
        {
            if(ex.name() == QStringLiteral("keyUsage"))
            {
                for(const QVariant &item: ex.value().toList())
                    if(item.toString() == QStringLiteral("Non Repudiation"))
                        isNonRepudiation = true;
            }
        }
        if (!isNonRepudiation) {
            return {{"result", "invalid_argument"}};
        }

        PKCS11CardManager::Token selected;
        PKCS11Path::Params p11 = PKCS11Path::getPkcs11ModulePath();
        PKCS11CardManager pkcs11(p11.path);
        try {
            for (const PKCS11CardManager::Token &token : pkcs11.tokens()) {
                if (token.cert == data) {
                    selected = token;
                    break;
                }
            }
        } catch (const BaseException &e) {
            qDebug() << e.what();
            return {{"result", QString::fromStdString(e.getErrorCode())}};
        }

        if(selected.cert.empty())
            return {{"result", "invalid_argument"}};

        QString label = Labels::l10n.get(selected.pinpad ? "sign PIN pinpad" : "sign PIN").c_str();
        label.replace("@PIN@", p11.signPINLabel.c_str());

        bool isInitialCheck = true;
        for (int retriesLeft = selected.retry; retriesLeft > 0; ) {
            Signer dialog(contents, label, selected.minPinLen, selected.pinpad);
            if (retriesLeft < 3) {
                dialog.errorLabel->show();
                dialog.errorLabel->setText(QStringLiteral("<font color='red'><b>%1%2 %3</b></font>")
                     .arg((!isInitialCheck ? Labels::l10n.get("incorrect PIN2") : "").c_str())
                     .arg(Labels::l10n.get("tries left").c_str())
                     .arg(retriesLeft));
            }
            isInitialCheck = false;
            dialog.nameLabel->setText(c.subjectInfo(QSslCertificate::CommonName).join(""));

            std::future< std::vector<unsigned char> > signature;

            /*
            * X509 certificate Base64 logic start
            */
            // X509 Base64 certificate PEM (without begin/end)
            QString x509pem = QString(c.toPem())
                .replace(QString("-----BEGIN CERTIFICATE-----\n"), QString(""))
                .replace(QString("-----END CERTIFICATE-----\n"), QString(""))
            ;
            std::string x509pemAsString = x509pem.toStdString();
            std::size_t lastNewlineOccurrence = x509pemAsString.find_last_of("\n");
            x509pemAsString = x509pemAsString.substr(0, lastNewlineOccurrence);
            /*
            * X509 certificate Base64 logic end
            */

            /*
            * X509 certificate Sha256 digest logic start
            */
            std::string x509sha256digest = c.digest(QCryptographicHash::Sha256).toBase64().toStdString();
            /*
            * X509 certificate Sha256 digest logic end
            */

            /*
            * Cert.IssuerSerial.X509IssuerName logic start
            */
            QString x509DN = "CN=" + c.issuerInfo(QSslCertificate::CommonName).join("") + ",organizationIdentifier=" + c.issuerInfo(QByteArray("organizationIdentifier")).join("") + ",O=" + 
                c.issuerInfo(QSslCertificate::Organization).join("") + ",C=" + c.issuerInfo(QSslCertificate::CountryName).join("");
            std::string x509DNasString = x509DN.toStdString();
            /*
            * Cert.IssuerSerial.X509IssuerName logic end
            */

            /*
            * X509 certificate Serial Number Logic start
            */
            // Get hex value (e.g. 43:67:b0:19:74:26:df:f6:5c:c0:3e:9d:03:3e:ee:13)
            std::string hex = c.serialNumber().toStdString();
            // Remove hex string separators (e.g. 4367b0197426dff65cc03e9d033eee13)
            size_t start_pos = 0;
            while((start_pos = hex.find(":", start_pos)) != std::string::npos) {
                hex.replace(start_pos, 1, "");
                start_pos += 1;
            }
            // Convert to uppercase (4367B0197426DFF65CC03E9D033EEE13)
            for (auto & c: hex) c = toupper(c);

            // Hexadecimal -> Decimal conversion
            const BaseConverter& hex2dec = BaseConverter::HexToDecimalConverter();
            std::string serialNoDecimal = hex2dec.Convert(hex.c_str());
            /*
            * X509 certificate Serial Number Logic end
            */

            /*
            * File Reference logic start
            */
            QByteArray fileContents = QByteArray::fromBase64(contents.toUtf8());
            QByteArray fileContentsDigest = QCryptographicHash::hash(fileContents, QCryptographicHash::Sha256);
            /*
            * File Reference logic end
            */

            // Creating of XML
            rapidxml::xml_document<> doc;
            
            std::string randomId = random_string(24);
            const char* signatureId = randomId.c_str();
            _log("Generated random id %s", randomId.c_str());
            const char* fileURI = "document.txt";

            // XML declaration
            rapidxml::xml_node<> *xmlDeclarationNode = doc.allocate_node(rapidxml::node_declaration);
            xmlDeclarationNode->append_attribute(doc.allocate_attribute("version", "1.0"));
            xmlDeclarationNode->append_attribute(doc.allocate_attribute("encoding", "UTF-8"));
            xmlDeclarationNode->append_attribute(doc.allocate_attribute("standalone", "no"));
            doc.append_node(xmlDeclarationNode);

            // asic:XAdESSignatures
            rapidxml::xml_node<> *root = doc.allocate_node(rapidxml::node_element, "asic:XAdESSignatures");
            root->append_attribute(doc.allocate_attribute("xmlns:asic", "http://uri.etsi.org/02918/v1.2.1#"));
            root->append_attribute(doc.allocate_attribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#"));
            root->append_attribute(doc.allocate_attribute("xmlns:xades", "http://uri.etsi.org/01903/v1.3.2#"));
            doc.append_node(root);

            // ds:Signature
            rapidxml::xml_node<> *signatureNode = doc.allocate_node(rapidxml::node_element, "ds:Signature");
            signatureNode->append_attribute(doc.allocate_attribute("Id", signatureId));
            root->append_node(signatureNode);

            // Signature->SignedInfo
            rapidxml::xml_node<> *signedInfo = doc.allocate_node(rapidxml::node_element, "ds:SignedInfo");
            signatureNode->append_node(signedInfo);

            // Signature->KeyInfo
            rapidxml::xml_node<> *keyInfo = doc.allocate_node(rapidxml::node_element, "ds:KeyInfo");
            signatureNode->append_node(keyInfo);

            // Signature->KeyInfo->X509Data
            rapidxml::xml_node<> *x509Data = doc.allocate_node(rapidxml::node_element, "ds:X509Data");
            keyInfo->append_node(x509Data);

            // Signature->KeyInfo->X509Data->X509Certificate
            rapidxml::xml_node<> *x509Certificate = doc.allocate_node(rapidxml::node_element, "ds:X509Certificate", x509pemAsString.c_str());
            x509Data->append_node(x509Certificate);

            // Signature->Object
            rapidxml::xml_node<> *object = doc.allocate_node(rapidxml::node_element, "ds:Object");
            signatureNode->append_node(object);

            // Signature->Object->QualifyingProperties
            std::string qualifyingPropertiesReference = "#";
            qualifyingPropertiesReference += signatureId;
            rapidxml::xml_node<> *qualifyingProperties = doc.allocate_node(rapidxml::node_element, "xades:QualifyingProperties");
            qualifyingProperties->append_attribute(doc.allocate_attribute("Target", qualifyingPropertiesReference.c_str()));
            object->append_node(qualifyingProperties);

            // Signature->Object->QualifyingProperties->SignedProperties
            std::string signedPropertiesId = signatureId;
            signedPropertiesId += "-SignedProperties";
            rapidxml::xml_node<> *signedProperties = doc.allocate_node(rapidxml::node_element, "xades:SignedProperties");
            signedProperties->append_attribute(doc.allocate_attribute("Id", signedPropertiesId.c_str()));
            qualifyingProperties->append_node(signedProperties);

            // Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties
            rapidxml::xml_node<> *signedSignatureProperties = doc.allocate_node(rapidxml::node_element, "xades:SignedSignatureProperties");
            signedProperties->append_node(signedSignatureProperties);

            // Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningTime
            std::string currentTimeUtc = toZuluTime();
            rapidxml::xml_node<> *signingTime = doc.allocate_node(rapidxml::node_element, "xades:SigningTime", currentTimeUtc.c_str());
            signedSignatureProperties->append_node(signingTime);

            // Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningCertificate
            rapidxml::xml_node<> *signingCertificate = doc.allocate_node(rapidxml::node_element, "xades:SigningCertificate");
            signedSignatureProperties->append_node(signingCertificate);

            // Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningCertificate.Cert
            rapidxml::xml_node<> *cert = doc.allocate_node(rapidxml::node_element, "xades:Cert");
            signingCertificate->append_node(cert);

            // Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningCertificate.Cert.CertDigest
            rapidxml::xml_node<> *certDigest = doc.allocate_node(rapidxml::node_element, "xades:CertDigest");
            cert->append_node(certDigest);

            // Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningCertificate.Cert.CertDigest.DigestMethod
            rapidxml::xml_node<> *certDigestMethod = doc.allocate_node(rapidxml::node_element, "ds:DigestMethod");
            certDigestMethod->append_attribute(doc.allocate_attribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256"));
            certDigest->append_node(certDigestMethod);

            // Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningCertificate.Cert.CertDigest.DigestValue
            rapidxml::xml_node<> *certDigestValue = doc.allocate_node(rapidxml::node_element, "ds:DigestValue", x509sha256digest.c_str());
            certDigest->append_node(certDigestValue);

            // Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningCertificate.Cert.IssuerSerial
            rapidxml::xml_node<> *issuerSerial = doc.allocate_node(rapidxml::node_element, "xades:IssuerSerial");
            cert->append_node(issuerSerial);

            // Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningCertificate.Cert.IssuerSerial.X509IssuerName
            rapidxml::xml_node<> *x509IssuerName = doc.allocate_node(rapidxml::node_element, "ds:X509IssuerName", x509DNasString.c_str());
            issuerSerial->append_node(x509IssuerName);

            // Signature->Object->QualifyingProperties->SignedProperties->SignedSignatureProperties->SigningCertificate.Cert.IssuerSerial.X509SerialNumber
            rapidxml::xml_node<> *x509SerialNumber = doc.allocate_node(rapidxml::node_element, "ds:X509SerialNumber", serialNoDecimal.c_str());
            issuerSerial->append_node(x509SerialNumber);

            // Signature->Object->QualifyingProperties->SignedProperties->SignedDataObjectProperties
            rapidxml::xml_node<> *signedDataObjectProperties = doc.allocate_node(rapidxml::node_element, "xades:SignedDataObjectProperties");
            signedProperties->append_node(signedDataObjectProperties);

            // Signature->Object->QualifyingProperties->SignedProperties->SignedDataObjectProperties->DataObjectFormat
            std::string dataObjectFormatRefId = "#";
            dataObjectFormatRefId += signatureId;
            dataObjectFormatRefId += "-RefId0";
            rapidxml::xml_node<> *dataObjectFormat = doc.allocate_node(rapidxml::node_element, "xades:DataObjectFormat");
            dataObjectFormat->append_attribute(doc.allocate_attribute("ObjectReference", dataObjectFormatRefId.c_str()));
            signedDataObjectProperties->append_node(dataObjectFormat);

            // Signature->Object->QualifyingProperties->SignedProperties->SignedDataObjectProperties->DataObjectFormat->MimeType
            rapidxml::xml_node<> *mimeType = doc.allocate_node(rapidxml::node_element, "xades:MimeType", "text/plain");
            dataObjectFormat->append_node(mimeType);

            // Signature->SignedInfo->CanonicalizationMethod
            rapidxml::xml_node<> *canonicalizationMethod = doc.allocate_node(rapidxml::node_element, "ds:CanonicalizationMethod");
            canonicalizationMethod->append_attribute(doc.allocate_attribute("Algorithm",
                                                                            "http://www.w3.org/2006/12/xml-c14n11"));
            signedInfo->append_node(canonicalizationMethod);

            // Signature->SignedInfo->SignatureMethod
            rapidxml::xml_node<> *signatureMethod = doc.allocate_node(rapidxml::node_element, "ds:SignatureMethod");
            signatureMethod->append_attribute(doc.allocate_attribute("Algorithm",
                                                                    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"));
            signedInfo->append_node(signatureMethod);

            // Signature->SignedInfo->Reference (the file to be signed)
            std::string fileReferenceId = signatureId;
            fileReferenceId += "-RefId0";
            rapidxml::xml_node<> *fileReference = doc.allocate_node(rapidxml::node_element, "ds:Reference");
            fileReference->append_attribute(doc.allocate_attribute("Id", fileReferenceId.c_str()));
            fileReference->append_attribute(doc.allocate_attribute("URI", fileURI));
            signedInfo->append_node(fileReference);

            // Signature->SignedInfo->Reference (the file to be signed)->DigestMethod
            rapidxml::xml_node<> *fileReferenceDigestMethod = doc.allocate_node(rapidxml::node_element, "ds:DigestMethod");
            fileReferenceDigestMethod->append_attribute(
                    doc.allocate_attribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256"));
            fileReference->append_node(fileReferenceDigestMethod);

            // Signature->SignedInfo->Reference (the file to be signed)->DigestValue
            const char* fileDigestConst = fileContentsDigest.toBase64().toStdString().c_str();
            std::string fileDigestAsStdString = fileContentsDigest.toBase64().toStdString();
            rapidxml::xml_node<> *fileReferenceDigestValue = doc.allocate_node(rapidxml::node_element, "ds:DigestValue", fileDigestConst);
            fileReference->append_node(fileReferenceDigestValue);

            // Signature->SignedInfo->Reference (SignedProperties)
            std::string signedPropertiesReferenceId = signatureId;
            signedPropertiesReferenceId += "-RefId1";
            std::string signedPropertiesReferenceUri = "#";
            signedPropertiesReferenceUri += signatureId;
            signedPropertiesReferenceUri += "-SignedProperties";
            rapidxml::xml_node<> *signedPropertiesReference = doc.allocate_node(rapidxml::node_element, "ds:Reference");
            signedPropertiesReference->append_attribute(doc.allocate_attribute("Id", signedPropertiesReferenceId.c_str()));
            signedPropertiesReference->append_attribute(doc.allocate_attribute("Type", "http://uri.etsi.org/01903#SignedProperties"));
            signedPropertiesReference->append_attribute(doc.allocate_attribute("URI", signedPropertiesReferenceUri.c_str()));
            signedInfo->append_node(signedPropertiesReference);

            // Signature->SignedInfo->Reference (SignedProperties)->DigestMethod
            rapidxml::xml_node<> *signedPropertiesReferenceDigestMethod = doc.allocate_node(rapidxml::node_element, "ds:DigestMethod");
            signedPropertiesReferenceDigestMethod->append_attribute(
                    doc.allocate_attribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256"));
            signedPropertiesReference->append_node(signedPropertiesReferenceDigestMethod);

            // Signature->SignedInfo->Reference (SignedProperties)->DigestValue
            // Read SignedProperties to stream, then convert to string

            // Make a copy of SignedProperties object for C14N
            rapidxml::xml_node<> *signedPropsForC14N = doc.allocate_node(rapidxml::node_element);
            doc.clone_node(signedProperties, signedPropsForC14N);
            // Add namespace attributes required for C14N
            signedPropsForC14N->prepend_attribute(doc.allocate_attribute("xmlns:xades", "http://uri.etsi.org/01903/v1.3.2#"));
            signedPropsForC14N->prepend_attribute(doc.allocate_attribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#"));
            signedPropsForC14N->prepend_attribute(doc.allocate_attribute("xmlns:asic", "http://uri.etsi.org/02918/v1.2.1#"));

            std::stringstream signedPropertiesStringStream;
            signedPropertiesStringStream <<*signedPropsForC14N;
            std::string signedPropertiesAsString = signedPropertiesStringStream.str().erase(signedPropertiesStringStream.str().rfind("\n"));
            std::string::iterator end_pos = std::remove(signedPropertiesAsString.begin(), signedPropertiesAsString.end(), '\n');
            signedPropertiesAsString.erase(end_pos, signedPropertiesAsString.end());
            end_pos = std::remove(signedPropertiesAsString.begin(), signedPropertiesAsString.end(), '\t');
            signedPropertiesAsString.erase(end_pos, signedPropertiesAsString.end());
            signedPropertiesStringStream.str("");
            signedPropertiesStringStream.clear();
            QByteArray signedPropertiesArr = QByteArray(signedPropertiesAsString.c_str(), signedPropertiesAsString.length());
            QByteArray signedPropertiesDigest = QCryptographicHash::hash(signedPropertiesArr, QCryptographicHash::Sha256);
            std::string signedPropsDigest = signedPropertiesDigest.toBase64().toStdString();

            rapidxml::xml_node<> *signedPropertiesReferenceDigestValue = doc.allocate_node(rapidxml::node_element, "ds:DigestValue", signedPropsDigest.c_str());
            signedPropertiesReference->append_node(signedPropertiesReferenceDigestValue);

            // Make a copy of SignedInfo node for C14N
            rapidxml::xml_node<> *signedInfoForC14N = doc.allocate_node(rapidxml::node_element);
            doc.clone_node(signedInfo, signedInfoForC14N);
            // Add namespace attributes required for C14N
            signedInfoForC14N->prepend_attribute(doc.allocate_attribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#"));


            std::stringstream signedInfoStringStream;
            signedInfoStringStream <<*signedInfoForC14N;
            std::string signedInfoAsString = signedInfoStringStream.str().erase(signedInfoStringStream.str().rfind("\n"));
            end_pos = std::remove(signedInfoAsString.begin(), signedInfoAsString.end(), '\n');
            signedInfoAsString.erase(end_pos, signedInfoAsString.end());
            end_pos = std::remove(signedInfoAsString.begin(), signedInfoAsString.end(), '\t');
            signedInfoAsString.erase(end_pos, signedInfoAsString.end());
            signedInfoStringStream.str("");
            signedInfoStringStream.clear();

            QByteArray sigInfoArr = QByteArray(signedInfoAsString.c_str(), signedInfoAsString.length());
            QByteArray sigInfoDigest = QCryptographicHash::hash(sigInfoArr, QCryptographicHash::Sha256);

            std::string signedInfoDigest = sigInfoDigest.toBase64().toStdString();

            if (selected.pinpad) {
                signature = std::async(std::launch::async, [&]{
                    std::vector<unsigned char> result;
                    try {
                        result = pkcs11.sign(selected, fromBase64(contents), nullptr);
                        dialog.accept();
                    } catch (const AuthenticationError &) {
                        --retriesLeft;
                        dialog.done(AuthError);
                    } catch (const PinBlockedException &) {
                        retriesLeft = 0;
                        dialog.done(AuthError);
                    } catch (const AuthenticationBadInput &) {
                        dialog.done(AuthError);
                    } catch (const UserCancelledException &) {
                        dialog.done(UserCancel);
                    } catch (const BaseException &e) {
                        qDebug() << e.what();
                        dialog.setProperty("exception", QString::fromStdString(e.getErrorCode()));
                        dialog.done(TechnicalError);
                    }
                    return result;
                });
            }

            switch (dialog.exec())
            {
            case UserCancel:
                return {{"result", "user_cancel"}};
            case AuthError:
                continue;
            case TechnicalError:
                return {{"result", dialog.property("exception")}};
            default:
                if (selected.pinpad) {
                    return {{"signature", toHex(signature.get())}};
                }
            }

            try {
                if (!selected.pinpad) {
                    std::vector<unsigned char> result = pkcs11.sign(
                        selected, fromHex(QString(signedInfoDigest.c_str())), dialog.pin->text().toUtf8().constData());

                    // Signature->SignatureValue
                    std::string signatureValueId = signatureId;
                    signatureValueId +=  "-SIG";
                    const char* sigValId = signatureValueId.c_str();
                    QByteArray signatureAsHex = toHex(result);
                    std::string sigB64 = QByteArray::fromHex(signatureAsHex).toBase64().toStdString();
                    rapidxml::xml_node<> *signatureValue = doc.allocate_node(rapidxml::node_element, "ds:SignatureValue", sigB64.c_str());
                    signatureValue->append_attribute(doc.allocate_attribute("Id", sigValId));
                    signatureNode->insert_node(keyInfo, signatureValue);
                    // Signature->SignatureValue end

                    // XML to Base64
                    std::stringstream docStream;
                    docStream << doc;
                    std::string docString = docStream.str();
                    docStream.str("");
                    docStream.clear();

                    _log("XML \n %s", docString.c_str());
                    end_pos = std::remove(docString.begin(), docString.end(), '\n');
                    docString.erase(end_pos, docString.end());
                    end_pos = std::remove(docString.begin(), docString.end(), '\t');
                    docString.erase(end_pos, docString.end());

                    return {{"signature", QByteArray(docString.c_str(), docString.length()).toBase64()}};
                }
            } catch (const AuthenticationBadInput &) {
            } catch (const AuthenticationError &) {
                --retriesLeft;
            } catch (const UserCancelledException &) {
                return {{"result", "user_cancel"}};
            } catch (const BaseException &e) {
                qDebug() << e.what();
                return {{"result", QString::fromStdString(e.getErrorCode())}};
            }
        }
        return {{"result", "pin_blocked"}};
    }

private:
    static QByteArray toHex(const std::vector<unsigned char> &data)
    {
        return QByteArray::fromRawData((const char*)data.data(), int(data.size())).toHex();
    }

    static std::vector<unsigned char> fromHex(const QString &data)
    {
        QByteArray bin = QByteArray::fromHex(data.toLatin1());
        return std::vector<unsigned char>(bin.cbegin(), bin.cend());
    }

    static std::vector<unsigned char> fromBase64(const QString &data)
    {
        QByteArray bin = QByteArray::fromBase64(data.toUtf8());
        return std::vector<unsigned char>(bin.cbegin(), bin.cend());
    }

    // https://stackoverflow.com/a/12468109
    static std::string random_string( size_t length )
    {
        auto randchar = []() -> char
        {
            const char charset[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
            const size_t max_index = (sizeof(charset) - 1);
            return charset[ rand() % max_index ];
        };
        std::string str(length,0);
        std::generate_n( str.begin(), length, randchar );
        return str;
    }

    // https://stackoverflow.com/a/20619520/5942672
    static std::string toZuluTime() {
        std::time_t now = std::time(nullptr);
        std::tm *now_tm = std::gmtime(&now);
        char buf[42];
        std::strftime(buf, 42, "%Y-%m-%dT%H:%M:%SZ", now_tm);
        return buf;
    }

    static std::string b64decode(const void* data, const size_t len)
    {
        int B64index[256] = { 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,
        7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,
        0,  0,  0, 63,  0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };

        unsigned char* p = (unsigned char*)data;
        int pad = len > 0 && (len % 4 || p[len - 1] == '=');
        const size_t L = ((len + 3) / 4 - pad) * 4;
        std::string str(L / 4 * 3 + pad, '\0');

        for (size_t i = 0, j = 0; i < L; i += 4)
        {
            int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
            str[j++] = n >> 16;
            str[j++] = n >> 8 & 0xFF;
            str[j++] = n & 0xFF;
        }
        if (pad)
        {
            int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
            str[str.size() - 1] = n >> 16;

            if (len > L + 2 && p[L + 2] != '=')
            {
                n |= B64index[p[L + 2]] << 6;
                str.push_back(n >> 8 & 0xFF);
            }
        }
        return str;
    }

    Signer(const QString &contents, const QString &label, unsigned long minPinLen, bool isPinpad)
        : nameLabel(new QLabel(this))
        , errorLabel(new QLabel(this))
    {
        QVBoxLayout *layout = new QVBoxLayout(this);
        layout->addWidget(errorLabel);
        layout->addWidget(nameLabel);

        layout->addWidget(new QLabel("Review file contents before signing:", this));
        QTextBrowser *textDisplay = new QTextBrowser();
        std::string base64DecodedString = b64decode(contents.toStdString().c_str(), contents.toStdString().size());
        textDisplay -> setText(QString::fromStdString(base64DecodedString));
        layout->addWidget(textDisplay);

        layout->addWidget(new QLabel(label, this));

        setMinimumWidth(400);
        setWindowFlags(Qt::WindowStaysOnTopHint);
        errorLabel->setTextFormat(Qt::RichText);
        errorLabel->hide();

        if(isPinpad) {
            setWindowFlags((windowFlags()|Qt::CustomizeWindowHint) & ~Qt::WindowCloseButtonHint);
            QProgressBar *progress = new QProgressBar(this);
            progress->setRange(0, 30);
            progress->setValue(progress->maximum());
            progress->setTextVisible(false);

            QTimeLine *statusTimer = new QTimeLine(progress->maximum() * 1000, this);
            statusTimer->setCurveShape(QTimeLine::LinearCurve);
            statusTimer->setFrameRange(progress->maximum(), progress->minimum());
            connect(statusTimer, &QTimeLine::frameChanged, progress, &QProgressBar::setValue);
            statusTimer->start();

            layout->addWidget(progress);
        } else {
            QDialogButtonBox *buttons = new QDialogButtonBox(this);
            connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
            connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
            buttons->addButton(Labels::l10n.get("cancel").c_str(), QDialogButtonBox::RejectRole);
            QPushButton *ok = buttons->addButton("OK", QDialogButtonBox::AcceptRole);
            ok->setEnabled(false);

            pin = new QLineEdit(this);
            pin->setEchoMode(QLineEdit::Password);
            pin->setFocus();
            pin->setValidator(new QRegExpValidator(QRegExp(QString("\\d{%1,12}").arg(minPinLen)), pin));
            pin->setMaxLength(12);
            connect(pin, &QLineEdit::textEdited, ok, [=](const QString &text) {
                ok->setEnabled(text.size() >= int(minPinLen));
            });

            layout->addWidget(pin);
            layout->addWidget(buttons);
        }
        show();
    }

    QLabel *nameLabel, *errorLabel;
    QLineEdit *pin = nullptr;
};

const char* BaseConverter::binarySet_ = "01";
const char* BaseConverter::decimalSet_ = "0123456789";
const char* BaseConverter::hexSet_ = "0123456789ABCDEF";

BaseConverter::BaseConverter(const std::string& sourceBaseSet, const std::string& targetBaseSet) 
    : sourceBaseSet_(sourceBaseSet)
    , targetBaseSet_(targetBaseSet)
{
    if (sourceBaseSet.empty() || targetBaseSet.empty())
        throw std::invalid_argument("Invalid base character set");
}

const BaseConverter& BaseConverter::DecimalToBinaryConverter()
{
    static const BaseConverter dec2bin(decimalSet_, binarySet_);
    return dec2bin;
}

const BaseConverter& BaseConverter::BinaryToDecimalConverter()
{
    static const BaseConverter bin2dec(binarySet_, decimalSet_);
    return bin2dec;
}

const BaseConverter& BaseConverter::DecimalToHexConverter()
{
    static const BaseConverter dec2hex(decimalSet_, hexSet_);
    return dec2hex;
}

const BaseConverter& BaseConverter::HexToDecimalConverter()
{
    static const BaseConverter hex2dec(hexSet_, decimalSet_);
    return hex2dec;
}

std::string BaseConverter::Convert(std::string value) const
{
    unsigned int numberBase = GetTargetBase();
    std::string result;

    do
    {
        unsigned int remainder = divide(sourceBaseSet_, value, numberBase);
        result.push_back(targetBaseSet_[remainder]);
    }
    while (!value.empty() && !(value.length() == 1 && value[0] == sourceBaseSet_[0]));

    std::reverse(result.begin(), result.end());
    return result;
}

std::string BaseConverter::Convert(const std::string& value, size_t minDigits) const
{
    std::string result = Convert(value);
    if (result.length() < minDigits)
        return std::string(minDigits - result.length(), targetBaseSet_[0]) + result;
    else
        return result;
}

std::string BaseConverter::FromDecimal(unsigned int value) const
{
    return dec2base(targetBaseSet_, value);
}

std::string BaseConverter::FromDecimal(unsigned int value, size_t minDigits) const
{
    std::string result = FromDecimal(value);
    if (result.length() < minDigits)
        return std::string(minDigits - result.length(), targetBaseSet_[0]) + result;
    else
        return result;
}

unsigned int BaseConverter::ToDecimal(std::string value) const
{
    return base2dec(sourceBaseSet_, value);
}

unsigned int BaseConverter::divide(const std::string& baseDigits, std::string& x, unsigned int y)
{
    std::string quotient;

    size_t lenght = x.length();
    for (size_t i = 0; i < lenght; ++i)
    {
        size_t j = i + 1 + x.length() - lenght;
        if (x.length() < j)
            break;

        unsigned int value = base2dec(baseDigits, x.substr(0, j));

        quotient.push_back(baseDigits[value / y]);
        x = dec2base(baseDigits, value % y) + x.substr(j);
    }

    // calculate remainder
    unsigned int remainder = base2dec(baseDigits, x);

    // remove leading "zeros" from quotient and store in 'x'
    size_t n = quotient.find_first_not_of(baseDigits[0]);
    if (n != std::string::npos)
    {
        x = quotient.substr(n);
    }
    else
    {
        x.clear();
    }

    return remainder;
}

std::string BaseConverter::dec2base(const std::string& baseDigits, unsigned int value)
{
    unsigned int numberBase = (unsigned int)baseDigits.length();
    std::string result;
    do 
    {
        result.push_back(baseDigits[value % numberBase]);
        value /= numberBase;
    } 
    while (value > 0);

    std::reverse(result.begin(), result.end());
    return result;
}

unsigned int BaseConverter::base2dec(const std::string& baseDigits, const std::string& value)
{
    unsigned int numberBase = (unsigned int)baseDigits.length();
    unsigned int result = 0;
    for (size_t i = 0; i < value.length(); ++i)
    {
        result *= numberBase;
        int c = baseDigits.find(value[i]);
        if (c == std::string::npos)
            throw std::runtime_error("Invalid character");

        result += (unsigned int)c;
    }

    return result;
}