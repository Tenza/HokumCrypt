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

#ifndef HOKUMCRYPT_H
#define HOKUMCRYPT_H

#include <QMainWindow>

namespace Ui {
    class HokumCrypt;
}

/**
 * @brief The HokumCrypt class
 *      This class implements all the user interface interactions.
 * @todo
 *      Exceptions.
 *      Currently this class also implements a single method to encrypt/decrypt,
 *      separate this to a new class.
 */
class HokumCrypt : public QMainWindow
{
    Q_OBJECT

public:
    explicit HokumCrypt(QWidget *parent = 0);
    ~HokumCrypt();

private:
    void work(const int type, const QByteArray hash);

    QString get_name(const QString filename);
    QString get_password(const QString last_password);

    QByteArray get_hash(const QString password) const;
    bool check_password(const QByteArray hash) const;

    void set_ui(const int lock_type, const QString text) const;

    QString filepath;
    QString filename;
    QString password;

    Ui::HokumCrypt *ui;

private slots:
    void on_btn_crypt_clicked();
    void on_btn_decrypt_clicked();
    void on_btn_browse_clicked();

};

#endif // HOKUMCRYPT_H
