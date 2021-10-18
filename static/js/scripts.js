    // ecb form submission
    $("#ecbform").submit(function(evt){	 
      evt.preventDefault();
      var formData = new FormData($(this)[0]);
      formData.append("mode",$("#aes-ecb-mode").text().trim())
    $.ajax({
        url: '/upload',
        type: 'POST',
        data: formData,
        async: false,
        cache: false,
        contentType: false,
        enctype: 'multipart/form-data',
        processData: false,
        success: function (response) {
          let filepath = response['result'];
          let explanation = response['result']['explanation']
          console.log(data['result']);
          $('#ebc-before-img').attr("src", "/"+filepath['originalfile']);
          $("#ebc-after-img").attr("src", "/"+filepath['encryptedfile']);
          $("#working_img").attr("src","{{ url_for('static', filename="+explanation['img']+")}}");
          $("#working_explanation").innerHTML(explanation['explanation']);
          $("#modalTitle").val(explanation['title']);
        }
    });
    return false;
    });


    function submitValue() {
      var textData = $("#resultText").val();
      if (textData[0] == '*' || textData[0] == '/' || textData[0] == '-' || textData[0] == '+') {
        alert('Cant have first character as operation');
        cleartext();
        return;
      }
      else if (textData.length == 0) {
        alert("Operation cant be empty");
      }
      else {
        if (textData.length != 0) {
          $.ajax({
            url: '/calculate',
            dataType: 'json',
            type: 'post',
            contentType: 'application/json',
            data: JSON.stringify({ "data": textData }),
            processData: false,
            success: function (data, textStatus, jQxhr) {
              $('#resultText').val(data['result']);
            },
            error: function (jqXhr, textStatus, errorThrown) {
              console.log(errorThrown);
            }
          });
        }
      }
    }

    function generate() {
      var low = $("#lower-limit").val();
      var high = $("#upper-limit").val();
      if (isNaN(low) == true || low.length == 0) {
        alert("Lower limit has to be a number");
      }
      else if (isNaN(high) == true || high.length == 0) {
        alert("Higher Limit has to be a number")
      }
      else {
        $.ajax({
          url: '/prime',
          dataType: 'json',
          type: 'post',
          contentType: 'application/json',
          data: JSON.stringify({ "lower": low, "higher": high }),
          processData: false,
          success: function (data, textStatus, jQxhr) {
            $('#primeresult').val(data['result']);
          },
          error: function (jqXhr, textStatus, errorThrown) {
            console.log(errorThrown);
          }
        });
      }
    }

    function rsa_generate() {
      var p = $("#pvalue").val();
      var q = $("#qvalue").val();
      if (isNaN(p) == true || p.length == 0) {
        alert("Please enter a value for p");
      }
      else if (isNaN(q) == true || q.length == 0) {
        alert("Please enter a value for q");
      }
      else {
        $.ajax({
          url: '/rsagenerate',
          dataType: 'json',
          type: 'post',
          contentType: 'application/json',
          data: JSON.stringify({ "p": p, "q": q }),
          processData: false,
          success: function (data, textStatus, jQxhr) {
            //$('#primeresult').val(data['result']);
            var result = data['result'];
            $('#nvalue').val(result['nvalue']);
            $('#lvalue').val(result['lvalue']);
            var evalue = result['encryptkeys'];
            $('#evalue').val(evalue);
            var dvalue = result['decryptkeys'];
            $('#dvalue').val(dvalue);
            $('#pvkey').val($('#evalue').val() + "," + $('#nvalue').val());
            $('#pbkey').val($('#dvalue').val() + "," + $('#nvalue').val())

          },
          error: function (jqXhr, textStatus, errorThrown) {
            console.log(errorThrown);
          }
        });

      }


    }

    function encrypt_message() {
      var text = $('#encrpyt-text').val().trim();
      if (text.length == 0) {
        alert("Please enter a message");
      }
      else {
        $.ajax({
          url: '/rsaencrypt',
          dataType: 'json',
          type: 'post',
          contentType: 'application/json',
          data: JSON.stringify({ "text": text, "evalue": $('#evalue').val(), "nvalue": $('#nvalue').val() }),
          processData: false,
          success: function (data, textStatus, jQxhr) {
            var result = data['result'];
            $("#ascii-message").val(result['ascii_value']);
            $("#message-encrypted").val(result['encrypted_text']);
            var enc_message = $("#message-encrypted").val();
            $("#decrpyt-text").val(enc_message);
          },
          error: function (jqXhr, textStatus, errorThrown) {
            console.log(errorThrown);
          }
        });
      }
    }

    function decrypt_message() {
      var text = $('#decrpyt-text').val().trim();
      if (text.length == 0) {
        alert("Please enter a message to decrypt");
      }
      else {
        $.ajax({
          url: '/rsadecrypt',
          dataType: 'json',
          type: 'post',
          contentType: 'application/json',
          data: JSON.stringify({ "text": text, "dvalue": $('#dvalue').val(), "nvalue": $('#nvalue').val() }),
          processData: false,
          success: function (data, textStatus, jQxhr) {
            var result = data['result'];
            $("#decryptascii-message").val(result['ascii_value']);
            $("#message-decrypted").val(result['decrypted_text']);
            //var enc_message = $("#message-encrypted").val();
            //$("#decrpyt-text").val(enc_message);
          },
          error: function (jqXhr, textStatus, errorThrown) {
            console.log(errorThrown);
          }
        });
      }
    }

    function aesEncrypt() {
      var text = $('#aes-message').val().trim();
      var secret = $('#aes-password').val().trim();
      var mode = $('#aes-mode').text().trim();
      if (text.length == 0 && secret.length == 0) {
        alert("Please enter a message and/or secret key to encrypt");
      }
      else {
        $.ajax({
          url: '/aesencrypt',
          dataType: 'json',
          type: 'post',
          contentType: 'application/json',
          data: JSON.stringify({ "text": text, "secretkey": secret, "mode": mode }),
          processData: false,
          success: function (data, textStatus, jQxhr) {
            $("#aes-cipher").val(data['result']['aescipher']['ciphertext']);
            $("#aes-cipher").text(data['result']['aescipher']['ciphertext']);
            //var enc_message = $("#message-encrypted").val();
            //$("#decrpyt-text").val(enc_message);
          },
          error: function (jqXhr, textStatus, errorThrown) {
            console.log(errorThrown);
          }
        });
      }
    }

    function aesDecrypt() {
      var secret = $('#aes-cipher-decrypt').val().trim();
      var mode = $('#aes-mode').text().trim();
      if (secret.length == 0) {
        alert("Please enter a secret key to Decrypt");
      }
      else {
        $.ajax({
          url: '/aesdecrypt',
          dataType: 'json',
          type: 'post',
          contentType: 'application/json',
          data: JSON.stringify({ "cipher": $('#aes-cipher').val(), "secretkey": secret, "mode": mode }),
          processData: false,
          success: function (data, textStatus, jQxhr) {

            $("#decryptaes-message").val(data['result']['aesdecipher']);
          },
          error: function (jqXhr, textStatus, errorThrown) {
            console.log(errorThrown);
          }
        });
      }
    }

    function desEncrypt() {
      var text = '';
      var secret = ''
      var keychecks = true;

      text = $('#des-message').val().trim();
      //check if the message is in multiple of 8, if not add padding
      if (text.length > 0 && text.length % 8 != 0) {
        let x = text.length % 8;
        // add padding to the text to make it multiple of 8
        text = text + ' '.repeat(x);
      }


      // check if the secret keys length is 16 or multiple of 16

      secret1 = $('#des-password1').val().trim();
      //check if key 1 is of length 16
      if ($('#des-password1').val().trim().length != 16) {
        keychecks = false;
        alert("Secret key 1 should be 16 characters long");
        $('#des-password1').css('border-color', 'red');
        return;
      }
      secret2 = $('#des-password2').val().trim();
      if ($('#des-password2').val().trim().length != 16) {
        keychecks = false;
        alert("Secret key 2 should be 16 characters long");
        $('#des-password2').css('border-color', 'red');
        return;
      }

      //$('#des-key1').attr("disabled",true);

      secret3 = $('#des-password3').val().trim();
      if ($('#des-password3').val().trim().length != 16) {
        keychecks = false;
        alert("Secret key 3 should be 16 characters long");
        $('#des-password3').css('border-color', 'red');
        return;
      }
      if (text.length == 0 && secret.length == 0 && !keychecks) {
        alert("Please enter a message and/or correct secret key to encrypt");
      }
      else {
        if (keychecks == true) {
          $.ajax({
            url: '/tripledesencrypt',
            dataType: 'json',
            type: 'post',
            contentType: 'application/json',
            data: JSON.stringify({
              "text": text, "secretkey1": secret1,
              "secretkey2": secret2, "secretkey3": secret3
            }),
            processData: false,
            success: function (data, textStatus, jQxhr) {
              $("#des-cipher").val(data['result']['descipher']);
            },
            error: function (jqXhr, textStatus, errorThrown) {
              console.log(errorThrown);
            }
          });
        }
      }

    }

    function tripleDesDecrypt() {
      var text = $('#des-cipher').val().trim();
      var secret1 = $('#des-password1').val().trim();
      var secret2 = $('#des-password2').val().trim();
      var secret3 = $('#des-password3').val().trim();
      if (text.length == 0 && secret.length == 0) {
        alert("Please enter a message and/or secret key to encrypt");
      }
      else {
        $.ajax({
          url: '/tripledesdecrypt',
          dataType: 'json',
          type: 'post',
          contentType: 'application/json',
          data: JSON.stringify({
            "cipher": text, "secretkey1": secret1,
            "secretkey2": secret2, "secretkey3": secret3
          }),
          processData: false,
          success: function (data, textStatus, jQxhr) {
            $("#decryptdes-message").val(data['result']['plaintext']);
          },
          error: function (jqXhr, textStatus, errorThrown) {
            console.log(errorThrown);
          }
        });
      }

    }

  function printExplanation(){
      printElement(document.getElementById("resultModal"));

    };

    function printElement(elem) {
      var domClone = elem.cloneNode(true);

      var $printSection = document.getElementById("printSection");

      if (!$printSection) {
        var $printSection = document.createElement("div");
        $printSection.id = "printSection";
        document.body.appendChild($printSection);
      }

      $printSection.innerHTML = "";
      $printSection.appendChild(domClone);
      window.print();
    }