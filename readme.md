Spring Security

1. Uurige sessiooniga rakenduse käitumist:

   a) käivitage rakendus;<br>
   b) avage Chrome brauser ja selle arendaja tööriistade (F12) alt Network sakk;<br>
   c) laadige aadress http://localhost:8080/ veenduge, et küpsist ei seata;<br>
   d) laadige aadress http://localhost:8080/api/count veenduge, et küpsis seatakse;<br>
   e) värskendage lehte ja veenduge, et seatud küpsis saadetakse koos päringuga;<br>
   f) kustutage küpsis. Chrome brauseris aadressiriba ees olevale hüüumärgile<br>
      klikates avaneb vastav võimalus;<br>
   g) värskendage lehte ja veenduge, et küpsist ei saadeta ja samas seatakse uus küpsis.<br><br>

2. Tehke nii, et päringud Springi controlleritele (nt. http://localhost:8080/api/home) 
   vajavad autentimist. Selleks lisage konfiguratsiooni:
   ```
     http.authorizeHttpRequests(conf -> conf
            .requestMatchers(mvc.matcher("/**")).authenticated());
   ```
   
   Kontrollige, et päring aadressile /api/home tagastab koodi 403.

   Kontrollige, et test apiUrlsNeedAuthentication()
   (failis src/test/java/test/SecurityIntegrationTest.java) läheb läbi.

3. Lisage erand aadressi /api/home kohta

    ```
    http.authorizeHttpRequests(conf -> conf
                .requestMatchers(mvc.matcher("/api/home")).permitAll()
                .requestMatchers(mvc.matcher("/api/**")).authenticated()
        );
    ```
   
   NB! Erand peab olema enne üldist reeglit.

   Kontrollige, et erand toimib (päring õnnestub).

   Kontrollige, et test apiHomeDoesNotNeedAuthentication() läheb läbi.

4. Tehke nii, et rakendus näitaks sisselogimise vormi, kui ligipääs 
   puudub. Selleks lisage konfiguratsiooni:

   ```
   http.formLogin(Customizer.withDefaults());
   ```
   
   Kontrollige, et aadressile /api/info minnes saate koodi 302 ja teid 
   suunatakse sisselogimise vormile.

   Kontrollige, et test redirectsToLoginForm() läheb läbi.

5. Lisage kasutaja nimega "user", salasõnaga "123" ja rolliga "USER" 
   ning kasutaja nimega "admin", salasõnaga "123" ja rollidega "USER" ja "ADMIN".

   Selleks peate lisama konfiguratsiooni järgmise deklaratsiooni:

   ```
   @Bean
   public UserDetailsService userDetailService() {
       UserDetails user = User.builder()
               .username("user")
               .password("$2a$10...")
               .roles("USER")
               .build();
   
       UserDetails admin = User.builder()
               .username("admin")
               .password("$2a$...")
               .roles("USER", "ADMIN")
               .build();
   
       return new InMemoryUserDetailsManager(user, admin);
   }
   ```
   
   Räsi arvutamise näide on testide klassis test.PasswordEncoderTest.
   
   Minge aadressile /api/info. Rakendus peaks näitama sisselogimise vormi.
   Logige sisse kasutajaga "user". Teid peaks tagasi suunatama aadressile 
   /api/info.
   
   Kontrollige, et test canLoginWithCorrectPassword() läheb läbi.
   
6. Lisage piirang, et aadressilt /api/admin/** olevat infot näiks ainult
   kasutaja kellel on "ADMIN" roll.

   ```
   .requestMatchers("/admin/**").hasRole("ADMIN")
   ```
   
   Kontrollige, et sisse logides ei näe kasutaja infot aadressilt /api/admin/info
   aga admin näeb.
   
   Kontrollige, et test adminCanSeeMoreInfo() läheb läbi.
   
7. Lisage väljalogimise võimalus

   ```  
   http.logout(conf -> conf.logoutUrl("/api/logout"));
   ```  
   
   Väljalogimiseks tuleb teha post päring aadressile "/api/logout".
   
   Toorikus on kaasas vorm (aadressil /static/form.html), mis vastava päringu teeb.
   Et vorm poleks parooliga kaitstud lisage erand:
   
   ```
   .requestMatchers("/static/**").permitAll()
   ```
   
   Vormi postitamisel on automaatne CSRF kaitse. Lülitage see välja

   ```
   http.csrf(AbstractHttpConfigurer::disable);
   ```
     
   Kontrollige, et ka test canLogOut() läheb läbi.

Järgmiste ülesannete käigus muudate raamistiku käitumise sobivaks 
api-põhisele rakendusele.

8. Tehke nii, ligipääsu puudumisel ei suunata sisselogimise vormile vaid 
   tagastatakse vea kood (401).

   ```
      http.exceptionHandling(conf -> conf
        .authenticationEntryPoint(new ApiEntryPoint())
        .accessDeniedHandler(new ApiAccessDeniedHandler()));
   ```

   Kontrollige, et test doesNotShowLoginForm() läheb läbi.

9. Tehke nii, et väljalogimine ei suuna kuhugi ja tagastab koodi 200

   ```
      http.logout(conf -> conf
         .logoutSuccessHandler(new ApiLogoutSuccessHandler())
         .logoutUrl("/api/logout"));
   ```

   Kontrollige, et test logOutDoesNotRedirect() läheb läbi.
   
10. Lisage sisselogimise teenus aadressiga /api/login.
   
   Vajalik info saadetakse Json kujul

    ```     
    { "username": "user", "password": "secret" }
    ```

   Konfiguratsiooniks on vajalik lülitada välja csrf kontroll (tehtud 6. punktis)

    ```
    http.csrf(AbstractHttpConfigurer::disable);
    ```     
   
   Lisada filter, mis reageerib aadressile "/api/login" päringule.
   Need muudatused peate tegema siseklassi FilterConfigurer configure() 
   meetodis.   

   ```
   var loginFilter = new ApiAuthenticationFilter(
      manager, "/api/login");
  
   http.addFilterBefore(loginFilter,
          UsernamePasswordAuthenticationFilter.class);
   ```
  
Lisaks peate kirjutama klassi ApiAuthenticationFilter vajaliku koodi 
(kuhu ja mida kirjutada on kommentaarides kirjas)

Kui sisend ei ole oodatud info oodatud kujul, saab sellest märku anda 
erindiga BadCredentialsException.   

Kontrollige Postman-iga ja testiga canLoginWithJsonRequest().
   
11. Aadressilt /api/users/\<user name\> on võimalik küsida konkreetse kasutaja infot.
   Tehke nii, et näidatakse infot vaid sisseloginud kasutaja kohta.
   
   Nt. kui olen sisse loginud kasutajana "user" ja pöördun aadressile
   /api/users/user, siis näen vastavat infot, kui aga pöördun aadressile
   /api/users/alice, siis saan vea (http koodiga 401)
   
   Konfiguratsiooniks on vaja annotatsiooni Spring-i konfiguratsiooni klassil

   ```@EnableMethodSecurity```

   ja annotatsiooni kontrolleri meetodil
  
   ```@PreAuthorize("#username == authentication.name")```
      
   Kontrollige Postman-iga ja testiga userCanSeeOnlyOwnInfo().

12. Pange rakendus kasutama Jwt-põhist autoriseerimist.

   ApiAuthenticationFilter-i asemel peaks kasutama JwtAuthenticationFilter-it.
   
   See filter pärineb ApiAuthenticationFilter-ist ja kasutab ära viimase 
   attemptAuthentication() meetodi, mida täiendasite punktis 9. Lisaks 
   genereerib see token-i ja paneb selle Http vastuse päisesse.
   
   See filter vajab ka võtit krüpteerimiseks. Võti on application.properties
   failis ja selle saate Spring-i konkfiguratsiooni süstida.
   
   ```
   @Value("${jwt.signing.key}")
   private String jwtKe
   ```

   saks peate lisama JwtAuthorizationFilter-i, mis päringus oleva tokit 
   ntrollib järgi sissepääsu otsuse teeb.

   ```     
   var authorizationFilter = new JwtAuthorizationFilter(jwtKey);
    
   http.addFilterBefore(authorizationFilter, AuthorizationFilter.class);
   ```
   
   Kontrollige Postman-iga ja testiga canAccessWithJwtToken().

Lahendused ja seletused: https://youtu.be/3hm17aNsqYs
