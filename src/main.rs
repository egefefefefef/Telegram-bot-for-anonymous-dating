use std::collections::HashMap;
use std::sync::Arc;
use teloxide::{prelude::*, types::{InlineKeyboardButton, InlineKeyboardMarkup, UserId}, utils::command::BotCommands};
use dotenv::dotenv;
use tokio::sync::Mutex;
use rand::{RngCore, thread_rng};

// --- Библиотеки для шифрования на чистом Rust ---
use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};

// --- Структуры для хранения состояния ---

#[derive(Clone)]
struct PartnerInfo {
    partner_id: UserId,
    key: [u8; 32],
}

#[derive(Clone, Default)]
struct State {
    queue: Vec<UserId>,
    pairs: HashMap<UserId, PartnerInfo>,
}

impl State {
    fn new() -> Self { Self::default() }
}

type AppState = Arc<Mutex<State>>;

// --- Команды бота ---

#[derive(BotCommands, Clone)]
#[command(rename_rule = "lowercase", description = "Доступные команды:")]
enum Command {
    #[command(description = "Показать приветственное сообщение и кнопки.")]
    Start,
}

// --- Основная функция ---

#[tokio::main]
async fn main() {
    dotenv().ok();
    let token = std::env::var("TOKEN").expect("Переменная окружения TOKEN не найдена");
    let bot = Bot::new(token);

    // ИЗМЕНЕНО: Исправлен синтаксис создания состояния
    let state = Arc::new(Mutex::new(State::new()));

    let handler = dptree::entry()
        .branch(Update::filter_message().filter_command::<Command>().endpoint(command_handler))
        .branch(Update::filter_callback_query().endpoint(callback_handler))
        .branch(Update::filter_message().endpoint(message_handler));

    println!("Бот запускается...");

    Dispatcher::builder(bot, handler)
        .dependencies(dptree::deps![state])
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;
}

// --- Обработчики ---

async fn command_handler(bot: Bot, msg: Message, _cmd: Command) -> ResponseResult<()> {
    let keyboard = make_keyboard();
    bot.send_message(
        msg.chat.id,
        "Добро пожаловать в анонимный чат-бот!\n\nНажмите 'Найти собеседника', чтобы начать поиск."
    )
    .reply_markup(keyboard)
    .await?;
    Ok(())
}

async fn callback_handler(bot: Bot, q: CallbackQuery, state: AppState) -> ResponseResult<()> {
    let user_id = q.from.id;
    let chat_id = q.message.as_ref().unwrap().chat.id;

    if let Some(data) = q.data {
        match data.as_str() {
            "search" => {
                bot.answer_callback_query(q.id).text("Ищем собеседника...").await?;
                let mut s = state.lock().await;

                if s.pairs.contains_key(&user_id) {
                    bot.send_message(chat_id, "Вы уже в чате.").await?;
                    return Ok(());
                }
                if s.queue.contains(&user_id) {
                    bot.send_message(chat_id, "Вы уже в очереди.").await?;
                    return Ok(());
                }

                s.queue.push(user_id);
                bot.send_message(chat_id, "Вы добавлены в очередь. Ожидайте...").await?;

                if s.queue.len() >= 2 {
                    let u1_id = s.queue.remove(0);
                    let u2_id = s.queue.remove(0);
                    
                    let mut key = [0u8; 32];
                    thread_rng().fill_bytes(&mut key);
                    
                    let partner1_info = PartnerInfo { partner_id: u2_id, key };
                    let partner2_info = PartnerInfo { partner_id: u1_id, key };

                    s.pairs.insert(u1_id, partner1_info);
                    s.pairs.insert(u2_id, partner2_info);
                    
                    drop(s);

                    bot.send_message(ChatId(u1_id.0 as i64), "Собеседник найден! Начинайте общаться.").await?;
                    bot.send_message(ChatId(u2_id.0 as i64), "Собеседник найден! Начинайте общаться.").await?;
                }
            }
            "stop" => {
                bot.answer_callback_query(q.id).await?;
                let mut s = state.lock().await;

                if let Some(partner_info) = s.pairs.remove(&user_id) {
                    s.pairs.remove(&partner_info.partner_id);
                    drop(s);
                    bot.send_message(ChatId(partner_info.partner_id.0 as i64), "Ваш собеседник завершил чат.").await?;
                    bot.send_message(chat_id, "Вы завершили чат.").await?;
                } else if let Some(pos) = s.queue.iter().position(|&id| id == user_id) {
                    s.queue.remove(pos);
                    bot.send_message(chat_id, "Вы удалены из очереди.").await?;
                } else {
                    bot.send_message(chat_id, "Вы не находитесь в чате или в очереди.").await?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

async fn message_handler(bot: Bot, msg: Message, state: AppState) -> ResponseResult<()> {
    if let (Some(text), Some(user)) = (msg.text(), msg.from()) {
        let user_id = user.id;

        let partner_info = {
            let s = state.lock().await;
            s.pairs.get(&user_id).cloned()
        };

        if let Some(info) = partner_info {
            let iv = &info.key[0..16];
            
            // --- 1. Шифрование ---
            let plaintext = text.as_bytes();
            let mut buffer = vec![0u8; plaintext.len() + 16];
            buffer[..plaintext.len()].copy_from_slice(plaintext);

            let ciphertext = Aes256CbcEnc::new(&info.key.into(), iv.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
                .expect("Ошибка шифрования");
            
            // --- 2. Расшифровка ---
            let mut decrypt_buffer = ciphertext.to_vec();

            let decrypted_result = Aes256CbcDec::new(&info.key.into(), iv.into())
                .decrypt_padded_mut::<Pkcs7>(&mut decrypt_buffer);
            
            // --- 3. Обработка результата и отправка ---
            let original_text = match decrypted_result {
                Ok(bytes) => String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| "Ошибка: Некорректное UTF-8 сообщение".to_string()),
                Err(_) => "Ошибка расшифровки на стороне сервера.".to_string(),
            };
            
            bot.send_message(info.partner_id, original_text).await?;
        }
    }
    Ok(())
}

// --- Вспомогательные функции ---

fn make_keyboard() -> InlineKeyboardMarkup {
    let mut keyboard: Vec<Vec<InlineKeyboardButton>> = vec![];
    let buttons = vec![
        InlineKeyboardButton::callback("Найти собеседника 🔎", "search"),
        InlineKeyboardButton::callback("Завершить чат ❌", "stop"),
    ];
    keyboard.push(buttons);
    InlineKeyboardMarkup::new(keyboard)
}