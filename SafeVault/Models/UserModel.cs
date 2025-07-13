using System.ComponentModel.DataAnnotations;

namespace Webapi.Models;

public class UserModel
{
    [Required]
    [StringLength(50, MinimumLength = 3)]
    [RegularExpression("^[a-zA-Z0-9_.-]+$")]
    public string Username { get; set; }

    [Required]
    [StringLength(100, MinimumLength = 12)]
    public string Password { get; set; }
}