<?php
/*
Plugin Name: Second Password Admin
Plugin URI: https://kodabra.unchikov.ru/second-password-for-admin/
Description: The second password for the admin
Author: Elena Unchikova
Version: 1.0.1
Author URI: https://kodabra.unchikov.ru/
*/ 
// Защита от прямого доступа.
     if ( ! defined( 'ABSPATH' ) ) { exit; }
	 
// **************************************************************		 
// Отсылаем на эл. почту сообщение о попытках залогиниться.	 
function monitoring_login_attempts(){   
    if( !empty($_POST['log']) and !empty($_POST['pwd']) ){
wp_mail('ваша_эл_почта', 'Попытка входа на сайт', $_POST["log"].':'.$_POST["pwd"].' '.date('d-m-Y h:m:s').' '.$_SERVER['REMOTE_ADDR']);		
    }
}
add_action('login_init', 'monitoring_login_attempts');
// **************************************************************
	
// Добавляем хук на событие аутентификации пользователя.
add_action( 'wp_login', 'second_password_login_check', 10, 2 );

function second_password_login_check( $user_login, $user ) {
    // Проверяем, является ли пользователь админом и установлен ли куки-файл.
    if ( ( in_array( 'administrator', (array) $user->roles ) ) && ( !isset($_COOKIE['second_password'] ) ) ) {
        // Если пользователь админ и не установлен куки-файл даём 3 попытки:

        // Указываем путь к файлу количества попыток ввода второго пароля
        $filePathsp =  __DIR__ . '/countpass/' . $user->ID . '.txt';
        // Читаем содержимое файла
        $fileContentsp = file_get_contents($filePathsp);
        // Преобразуем содержимое в число
        $numbersp = (int)$fileContentsp;
        // Проверяем, если число больше или равно 3
        if ($numbersp >= 3) {
            wp_clear_auth_cookie(); //разлогиниваем пользователя
			nocache_headers();
            wp_safe_redirect( wp_login_url() ); //перенаправляем пользователя на страницу логина
            exit;	
        } else {
		    nocache_headers();
            wp_redirect( home_url( '/second-password/' ) ); //перенаправляем пользователя на страницу ввода второго пароля
            exit;
        }
    }	      
}

// Добавляем хук на событие вывода содержимого страницы ввода второго пароля.
add_action( 'template_redirect', 'second_password_page_check' );

function second_password_page_check() {
    // Проверяем, открыта ли текущая страница ввода второго пароля, пользователь админ и не установлен куки-файл.
    if ( is_page( 'second-password' ) && ( current_user_can( 'manage_options' ) ) && ( !isset($_COOKIE['second_password'] ) ) ) {
        // Если да, то выводим форму ввода второго пароля.
        ?>
        <form method="post">           
            <input type="password" id="second_password" name="second_password" required>
            <br>
            <input type="submit" value="Отправить">
        </form>
        <?php

        // Проверяем, был ли отправлен второй пароль.
        if ( isset( $_POST['second_password'] ) ) {
		    $filenameidsp = get_current_user_id();			
            $filenamesp =  __DIR__ . '/countpass/' . $filenameidsp . '.txt';
            // Если да, то проверяем его правильность.
            $second_password = sanitize_text_field( $_POST['second_password'] );

            if ( $second_password === 'ваш_второй_пароль' ){
                // Если пароль правильный, то устанавливаем ли куки-файл и перенаправляем пользователя на домашнюю страницу.
				setcookie( 'second_password', time(), time()+31556926, COOKIEPATH, COOKIE_DOMAIN );
				if (file_exists($filenamesp)) {
                   $countsp = 0;
                   file_put_contents($filenamesp, $countsp);
                } 
                nocache_headers();				
                wp_redirect(home_url());
                exit;	                
            } else {
                // Если пароль неправильный
			    // Записываем попытку в файл "id_юзера".txt               
                if (file_exists($filenamesp)) {
                   $countsp = file_get_contents( $filenamesp);
                   file_put_contents($filenamesp, ++$countsp);
                } else {
                   $cntsp = 1;
                   file_put_contents($filenamesp, $cntsp);
                }                            
                wp_clear_auth_cookie(); //разлогиниваем пользователя
				nocache_headers();
                wp_safe_redirect( wp_login_url() ); //перенаправляем пользователя на страницу логина
                exit;				
            }
        }
	// Если текущая страница не является страницей second-password и пользователь еще не ввел второй пароль,
    // то разлогиниваем пользователя. 	
    } elseif ( ( current_user_can( 'manage_options' ) ) &&  ( !isset($_COOKIE['second_password'] ) ) ) {	
        wp_clear_auth_cookie(); //разлогиниваем пользователя
		nocache_headers();
        wp_safe_redirect( wp_login_url() ); //перенаправляем пользователя на страницу логина
        exit;	  	
} 
}

// Для запрета доступа к административной панели если нет куки-файла разлогиниваем пользователя.
function block_wp_admin() {
    if ( is_admin() && (!isset($_COOKIE['second_password'] )) ) {
       wp_clear_auth_cookie(); //разлогиниваем пользователя
	   nocache_headers();
       wp_safe_redirect( wp_login_url() ); //перенаправляем пользователя на страницу логина
       exit;
    }
}
add_action( 'init', 'block_wp_admin' );