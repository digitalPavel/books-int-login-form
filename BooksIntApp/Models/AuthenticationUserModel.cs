using System.ComponentModel.DataAnnotations;

namespace BooksIntApp.Models
{
    public class AuthenticationUserModel
    {
        //[Required(ErrorMessage = "Email Address is required.")]
        public string Login { get; set; }

        //[Required(ErrorMessage = "Password is required.")]
        public string Password { get; set; }
    }
}
