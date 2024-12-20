import tkinter as tk
from tkinter import messagebox

# Начальное значение для хэширования
INITIAL_HASH = 0
HASH_LENGTH = 32  # Длина хэша в символах
def simple_hash(previous_hash, message_block):
    combined = int(previous_hash) + sum(ord(char) for char in message_block)
    hash_str = str(combined)  # Преобразуем в строку
    return (hash_str * (HASH_LENGTH // len(hash_str) + 1))[:HASH_LENGTH]  # Обрезаем до фиксированной длины


def encrypt_message(message):
    message_blocks = message.split()  # Разделяем сообщение на блоки
    current_hash = str(INITIAL_HASH).zfill(HASH_LENGTH)
    hashes = []

    for block in message_blocks:
        current_hash = simple_hash(current_hash, block)
        hashes.append(current_hash)

    return hashes


def decrypt_message(hashes):
    return hashes

def process_text():
    message = plaintext_entry.get("1.0", tk.END).strip()
    if not message:
        messagebox.showerror("Ошибка", "Введите текст для шифрования.")
        return

    hashes = encrypt_message(message)

    hash_entry.delete(0, tk.END)
    hash_entry.insert(0, ' '.join(hashes))


def verify_hash():
    hashes = hash_entry.get().strip().split()
    if not hashes:
        messagebox.showerror("Ошибка", "Нет хэшей для проверки.")
        return

    decrypted = decrypt_message(hashes)
    messagebox.showinfo("Хэши", "Хэши сообщения: " + ', '.join(decrypted))


def check_message():
    original_hashes = hash_entry.get().strip().split()
    if not original_hashes:
        messagebox.showerror("Ошибка", "Нет хэшей для проверки.")
        return
    message = plaintext_entry.get("1.0", tk.END).strip()
    if not message:
        messagebox.showerror("Ошибка", "Введите текст для проверки.")
        return

    new_hashes = encrypt_message(message)

    if list(map(str, new_hashes)) == original_hashes:
        messagebox.showinfo("Результат", "Сообщение соответствует сохраненному хэшу.")
    else:
        messagebox.showerror("Ошибка", "Сообщение не соответствует сохраненному хэшу.")

# Интерфейс
root = tk.Tk()
root.title("Хэширование сообщений с использованием блоков")

plaintext_label = tk.Label(root, text="Исходный текст:")
plaintext_label.pack()
plaintext_entry = tk.Text(root, height=5, width=50)
plaintext_entry.pack()

encrypt_button = tk.Button(root, text="Зашифровать", command=process_text)
encrypt_button.pack()

hash_label = tk.Label(root, text="Хэши сообщения:")
hash_label.pack()
hash_entry = tk.Entry(root, width=50)
hash_entry.pack()

check_button = tk.Button(root, text="Проверить сообщение", command=check_message)
check_button.pack()

root.mainloop()