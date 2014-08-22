/*
 * HokumCrypt
 * Copyright (C) 2011 Filipe Carvalho
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "hokumcrypt.h"
#include "ui_hokumcrypt.h"

#include <QFileDialog>
#include <QIODevice>
#include <QInputDialog>
#include <QCryptographicHash>

HokumCrypt::HokumCrypt(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::HokumCrypt)
{
    ui->setupUi(this);
}

HokumCrypt::~HokumCrypt()
{
    delete ui;
}

/**
 * @brief HokumCrypt::on_btn_browse_clicked
 *      Get and test the file to encrypt or decrypt.
 */
void HokumCrypt::on_btn_browse_clicked()
{
    filepath = QFileDialog::getOpenFileName(this, "Choose a file to encrypt or decrypt", filepath, "Any files (*)");
    QFile test_file(filepath);

    if(test_file.open(QIODevice::ReadOnly))
    {
        QFileInfo info(filepath);
        filename = info.fileName();
        set_ui(1, "The file <b>" + filename + "</b> is ready.");
    }
    else
    {
        filepath = "";
        filename = "";
        set_ui(2, "Choose a file to encrypt or decrypt.");
    }

    ui->progress_bar->setValue(0);
}

/**
 * @brief HokumCrypt::on_btn_crypt_clicked
 *      Call all the functions for the encryption procedure.
 */
void HokumCrypt::on_btn_crypt_clicked()
{
    QByteArray hash = "";

    password = get_password(password);
    hash = get_hash(password);

    filename.append(".hcy");

    if(QFile::exists(filename))
    {
        filename = get_name(filename);
    }

    work(1, hash);
}

/**
 * @brief HokumCrypt::on_btn_decrypt_clicked
 *      Call all the functions for the decryption procedure.
 */
void HokumCrypt::on_btn_decrypt_clicked()
{
    QByteArray hash = "";
    QFileInfo info(filepath);

    if(info.suffix() == "hcy")
    {
        password = get_password(password);
        hash = get_hash(password);

        if(check_password(hash))
        {
            filename.remove(filename.length() - 4, filename.length());

            if(QFile::exists(filename))
            {
                filename = get_name(filename);
            }

            work(2, hash);
        }
        else
        {
            set_ui(1, "<font color=\"red\"><b>Wrong password!</b></font>");
        }
    }
    else
    {
        set_ui(1, "<font color=\"red\">Extension not recognized for decryption.</font>");
    }
}

/**
 * @brief HokumCrypt::work
 *      Function that encrypts or decryptps the current file.
 * @param type
 *      1=encrypt 2=decrypt
 * @param hash
 *      In encryption add the hash to the file.
 *      In decryption take the hash out of the file.
 */
void HokumCrypt::work(const int type, const QByteArray hash)
{
    //Number of bytes to process on each block of data.
    unsigned short int buffersize = 1024;

    //File to read
    QFile read_file(filepath);
    qint64 read_position = 0;
    qint64 read_bytes = 0;
    QScopedArrayPointer<char> read_buffer(new char [buffersize]); //array to store the readed bytes

    //File to write
    QFile write_file(filename);
    short int current_byte = 0;
    QScopedArrayPointer<char> write_buffer(new char [buffersize]); //array to store the new bytes

    //Progress bar
    double progress = 0;
    double progress_add = 0;
    progress = read_file.size() / buffersize;
    progress = 100 / progress;

    unsigned short int password_shift = 0;

    if(read_file.open(QIODevice::ReadOnly) && write_file.open(QIODevice::WriteOnly))
    {
        if(type == 1)
        {
            set_ui(3, "Encrypting...");
            write_file.write(hash, hash.length());
        }
        else if(type == 2)
        {
            set_ui(3, "Decrypting...");
            read_position = hash.length();
        }

        //Loop the file blocks
        while(true)
        {
            read_file.seek(read_position);
            read_bytes = read_file.read(read_buffer.data(), buffersize);
            read_position += read_bytes;

            if(read_bytes == 0)
            {
                break;
            }

            //Loop every byte on the block
            for (int i = 0; i < read_bytes; i++)
            {
                //Shift the current byte by the current byte on the typed password.
                if(type == 1)
                {
                    current_byte = static_cast<quint8>(read_buffer[i]) + password[password_shift].toLatin1();

                    if(current_byte > 255)
                    {
                        current_byte -= 256;
                    }
                }
                else if(type == 2)
                {
                    current_byte = static_cast<quint8>(read_buffer[i]) - password[password_shift].toLatin1();

                    if(current_byte < 0)
                    {
                        current_byte += 256;
                    }
                }

                //Write new byte to the buffer
                write_buffer[i] = current_byte;

                if(password_shift == password.length() - 1)
                {
                    password_shift = 0;
                }
                else
                {
                    password_shift++;
                }
            }

            //Write the block to file
            write_file.write(write_buffer.data(), read_bytes);

            //Move the bar (this may freeze for big files, move the procedure to new thread)
            progress_add += progress;
            if(progress_add > 1)
            {
                progress_add = 0;
                ui->progress_bar->setValue(ui->progress_bar->value() + 1);
            }
        }

        ui->progress_bar->setValue(100);

        if(type == 1)
        {
            set_ui(2, "<font color=\"green\"><b>Encrypted Successfully!</b></font>");
        }
        else if(type == 2)
        {
            set_ui(2, "<font color=\"green\"><b>Decrypted Successfully!</b></font>");
        }
    }
    else
    {
        set_ui(2, "<font color=\"red\"><b>Was not possible to open/create the file.</b></font>");
    }

    filepath = "";
    filename = "";
    read_file.close();
    write_file.close();
}

/**
 * @brief HokumCrypt::get_name
 *      Function to change the name of the file.
 * @param filename
 *      Used to display the full name of the file, and to use its base to fill the box.
 * @return
 *      The new name, extension included.
 */
QString HokumCrypt::get_name(const QString filename)
{
    bool error = true;
    QString name = "";

    QFileInfo info(filename);

    while(error == true && name.isEmpty())
    {
        name = QInputDialog::getText(this,
                                    "File Name",
                                    "The file <b>" + filename + "</b> already exist.<br>Type a new name or overwrite the existing file.", QLineEdit::Normal, info.baseName(), &error);
    }

    name.append("." + info.completeSuffix());

    return name;
}

/**
 * @brief HokumCrypt::get_password
 *      Function to ask the password.
 * @param last_password
 *      The last used password, just to spare some work.
 * @return
 *      The password.
 */
QString HokumCrypt::get_password(const QString last_password)
{
    bool error = true;
    QString password = "";

    while(error == true && password.isEmpty())
    {
        password = QInputDialog::getText(this, "Password", "Type the password:", QLineEdit::Password, last_password, &error);
    }

    return password;
}

/**
 * @brief HokumCrypt::get_hash
 *      Function make the hashes the password in SHA3-512. Originaly it used SHA1.
 * @param password
 *      The password in clear text.
 * @return
 *      The hashed password.
 * @remarks
 *      Back in 2011, Qt didnt have SHA2 or SHA3 support in QCryptographicHash.
 *      The good thing is that it wasnt really necessary because even if a collision of
 *      hashes was found, in a rainbow table for example, you would still not be able to
 *      break the file, because the file is shifted with the original password and not the hash.
 */
QByteArray HokumCrypt::get_hash(const QString password) const
{
    QByteArray hash = password.toUtf8();

    hash = QCryptographicHash::hash(hash, QCryptographicHash::Sha3_512);
    hash = hash.toHex();

    return hash;
}

/**
 * @brief HokumCrypt::check_pass
 *      Function to check if the password matches the hash appended to the file.
 * @param pw_hash
 *      The hash of the password.
 * @return
 *      True=match, false=nomatch
 */
bool HokumCrypt::check_password(const QByteArray hash) const
{
    bool result = true;

    QFile read_file(filepath);
    QScopedArrayPointer<char> read_buffer(new char [hash.length()]);

    read_file.open(QIODevice::ReadOnly);
    read_file.read(read_buffer.data(), hash.length());

    for(int i=0; i < hash.length(); i++)
    {
        if(read_buffer[i] != hash[i])
        {
            result=false;
            break;
        }
    }

    read_file.close();
    return result;
}

/**
 * @brief HokumCrypt::set_ui
 *      Function to setup the UI.
 * @param lock_type
 *      The type of lock to be used.
 * @param text
 *      The message to display.
 */
void HokumCrypt::set_ui(const int lock_type, const QString text) const
{
    if(lock_type == 1)
    {
        ui->btn_browse->setEnabled(true);
        ui->btn_crypt->setEnabled(true);
        ui->btn_decrypt->setEnabled(true);
        ui->lbl_info->setText(text);
    }
    else if(lock_type == 2)
    {
        ui->btn_browse->setEnabled(true);
        ui->btn_crypt->setEnabled(false);
        ui->btn_decrypt->setEnabled(false);
        ui->lbl_info->setText(text);
    }
    else if(lock_type == 3)
    {
        ui->btn_browse->setEnabled(false);
        ui->btn_crypt->setEnabled(false);
        ui->btn_decrypt->setEnabled(false);
        ui->lbl_info->setText(text);
    }
}
