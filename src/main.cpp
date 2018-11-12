/*
 *  Copyright (C) 2010 Felix Geyer <debfx@fobos.de>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <QFile>

#include "config-keepassx.h"
#include "core/Config.h"
#include "core/qcommandlineparser.h"
#include "core/Tools.h"
#include "core/Translator.h"
#include "crypto/Crypto.h"
#include "gui/Application.h"
#include "gui/MainWindow.h"
#include "gui/MessageBox.h"
#include <seccomp.h> //EDIT:

int main(int argc, char** argv)
{

#ifdef QT_NO_DEBUG
    Tools::disableCoreDumps();
#endif
    Tools::setupSearchPaths();

    Application app(argc, argv);
    Application::setApplicationName("atomic"); //EDIT:
    Application::setApplicationVersion(KEEPASSX_VERSION);
    // don't set organizationName as that changes the return value of
    // QDesktopServices::storageLocation(QDesktopServices::DataLocation)


//EDIT:	
//required package "apt install libseccomp-dev", 
// add linker option -lseccomp in CMakeLists.txt "add_gcc_compiler_cxxflags("-Wnon-virtual-dtor -Wold-style-cast -Woverloaded-virtual -lseccomp")"
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
seccomp_arch_add(ctx, SCMP_ARCH_NATIVE);
//seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, pf));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 0);
//seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(clone), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(fork), 0);

seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(select), 0);
//seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(recvfrom), 0);
//seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(sendto), 0);
//seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(recvmsg), 0);
//seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(sendmsg), 0);
//seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socketcall), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(accept), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(connect), 0);
//seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socketpair), 0);

seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(bind), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(listen), 0);

seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(ioctl), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(execve), 0);

seccomp_load(ctx);
//EDIT:END

    QApplication::setQuitOnLastWindowClosed(false);

    if (!Crypto::init()) {
        QString error = QCoreApplication::translate("Main",
                                                    "Fatal error while testing the cryptographic functions.");
        error.append("\n");
        error.append(Crypto::errorString());
        MessageBox::critical(Q_NULLPTR, QCoreApplication::translate("Main", "Atomic - Error"), error); //EDIT:
        return 1;
    }

    QCommandLineParser parser;
    parser.setApplicationDescription(QCoreApplication::translate("main", "Atomic - cross-platform password manager")); //EDIT:
    parser.addPositionalArgument("filename", QCoreApplication::translate("main", "filename of the password database to open (*.kdbx)"));

    QCommandLineOption configOption("config",
                                    QCoreApplication::translate("main", "path to a custom config file"),
                                    "config");
    QCommandLineOption keyfileOption("keyfile",
                                     QCoreApplication::translate("main", "key file of the database"),
                                     "keyfile");

    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption(configOption);
    parser.addOption(keyfileOption);

    parser.process(app);
    const QStringList args = parser.positionalArguments();

    if (parser.isSet(configOption)) {
        Config::createConfigFromFile(parser.value(configOption));
    }

    Translator::installTranslator();

#ifdef Q_OS_MAC
    // Don't show menu icons on OSX
    QApplication::setAttribute(Qt::AA_DontShowIconsInMenus);
#endif

    MainWindow mainWindow;
    mainWindow.show();
    app.setMainWindow(&mainWindow);

    QObject::connect(&app, SIGNAL(openFile(QString)), &mainWindow, SLOT(openDatabase(QString)));

    if (!args.isEmpty()) {
        QString filename = args[0];
        if (!filename.isEmpty() && QFile::exists(filename)) {
            mainWindow.openDatabase(filename, QString(), parser.value(keyfileOption));
        }
    }

    if (config()->get("OpenPreviousDatabasesOnStartup").toBool()) {
        QStringList filenames = config()->get("LastOpenedDatabases").toStringList();
        Q_FOREACH (const QString& filename, filenames) {
            if (!filename.isEmpty() && QFile::exists(filename)) {
                mainWindow.openDatabase(filename, QString(), QString());
            }
        }
    }

    return app.exec();
}
