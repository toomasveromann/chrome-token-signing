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

#include <random>

#include "Signer.h"
#include "CertificateSelection.h"

#include <QApplication>
#include <QDebug>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QSocketNotifier>

#ifndef VERSION
#define VERSION "1.0.0.0"
#endif

class Application: public QApplication
{
public:
    Application(int &argc, char *argv[])
        : QApplication(argc, argv)
    {
        _log("Starting native host %s", VERSION);
        setWindowIcon(QIcon(":/chrome-token-signing.png"));
        setQuitOnLastWindowClosed(false);
        in.open(stdin, QFile::ReadOnly);
        QSocketNotifier *n1 = new QSocketNotifier(0, QSocketNotifier::Read, this);
        connect(n1, &QSocketNotifier::activated, this, &Application::parse);
    }

private:
    void parse();
    void write(QVariantMap &resp, const QString &nonce = QString()) const;
    std::string generateContainerName();
    void createContainer(QJsonValue base64, const char* path);
    int openContainerInDigiDoc4Client(std::string path, QJsonValue requestOrigin);
    QByteArray readContainer(const char* path);

    QFile in;
    QString origin, cert;
};

void Application::parse()
{
    uint32_t messageLength = 0;
    QVariantMap resp;

    if (in.atEnd()) {
      qDebug() << "Invalid empty message";
      resp = {{"result", "invalid_argument"}};
      write(resp);
      return exit(EXIT_FAILURE);
    }

    while (in.peek((char*)&messageLength, sizeof(messageLength)) > 0) {
        in.read((char*)&messageLength, sizeof(messageLength));
        QByteArray message = in.read(messageLength);
        _log("Message (%u): %s", messageLength, message.constData());
        QJsonObject json = QJsonDocument::fromJson(message).object();
        if(json.isEmpty()) {
            resp = {{"result", "invalid_argument"}};
            write(resp, json.value("nonce").toString());
            return exit(EXIT_FAILURE);
        }

        if(!json.contains("type") || !json.contains("nonce") || !json.contains("origin")) {
            resp = {{"result", "invalid_argument"}};
            write(resp, json.value("nonce").toString());
            return exit(EXIT_FAILURE);
        }

        if (origin.isEmpty()) {
            origin = json.value("origin").toString();
        } else if (origin != json.value("origin").toString()) {
            resp = {{"result", "invalid_argument"}};
            write(resp, json.value("nonce").toString());
            return exit(EXIT_FAILURE);
        }

        if (json.contains("lang")) {
            Labels::l10n.setLanguage(json.value("lang").toString().toStdString());
        }

        QString type = json.value("type").toString();
        if (type == "VERSION") {
            resp = {{"version", VERSION}};
        } else if (!json.value("origin").toString().startsWith("https:")) {
            resp = {{"result", "not_allowed"}};
            write(resp, json.value("nonce").toString());
            return exit(EXIT_FAILURE);
        }
        else if (type == "SIGN") {
            if (!json.contains("container")) {
                resp = {{"result", "invalid_argument"}};
            } else {
                std::string path = "/tmp/container-" + generateContainerName() + ".asice";
                createContainer(json.value("container"), path.c_str());
                int exitCode = openContainerInDigiDoc4Client(path, json.value("origin"));
                // Custom exit code stating whether or not user wishes to continue
                _log(("DigiDoc4 client exit code: " + std::to_string(exitCode)).c_str());
                if (exitCode != 14848) {
                    resp = {{"result", "user_cancel"}};
                } else {
                    QByteArray signedContainer = readContainer(path.c_str());
                    resp = {{"container", signedContainer.toBase64()}};
                }
            }
        } else if (type == "CERT") {
            if (json.value("filter").toString() == "AUTH") {
                resp = {{"result", "invalid_argument"}};
            } else {
                resp = CertificateSelection::getCert();
                cert = resp.value("cert").toString();
            }
        } else {
            resp = {{"result", "invalid_argument"}};
        }

        write(resp, json.value("nonce").toString());
    }
}

void Application::write(QVariantMap &resp, const QString &nonce) const
{
    if (!nonce.isEmpty())
        resp["nonce"] = nonce;

    if (!resp.contains("result"))
        resp["result"] = "ok";

    QByteArray response =  QJsonDocument::fromVariant(resp).toJson();
    uint32_t responseLength = uint32_t(response.size());
    _log("Response(%u) %s", responseLength, response.constData());
    QFile out;
    out.open(stdout, QFile::WriteOnly);
    out.write((const char*)&responseLength, sizeof(responseLength));
    out.write(response);
}

// Modified solution from https://stackoverflow.com/a/47978023/5942672
std::string Application::generateContainerName() {
    std::string alphabet("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
    std::random_device rd;
    std::mt19937 generator(rd());
    std::shuffle(alphabet.begin(), alphabet.end(), generator);
    return alphabet.substr(0, 32);
}

// Write temporary .asice container to /tmp/
void Application::createContainer(QJsonValue containerBase64, const char* path) {
    QByteArray data = QByteArray::fromBase64(containerBase64.toString().toUtf8());
    QSaveFile file(path);
    file.open(QIODevice::WriteOnly);
    file.write(data);
    file.commit();    
}

// Open temp file with qdigidoc4
int Application::openContainerInDigiDoc4Client(std::string path, QJsonValue requestOrigin) {
    char buffer[128];
    std::string result;
    std::string command = "qdigidoc4 -sign-only " + path + " -source " + requestOrigin.toString().replace("https://", "").replace(QRegularExpression(":[0-9]{1,}"), "").toStdString();
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != nullptr) {
        result += buffer;
    }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    return pclose(pipe);
}

// Read updated .asice container bytes and send response to service provider
QByteArray Application::readContainer(const char* path) {
    QFile container(path);
    container.open(QIODevice::ReadOnly);
    return container.readAll();
}

int main(int argc, char *argv[])
{
    return Application(argc, argv).exec();
}
