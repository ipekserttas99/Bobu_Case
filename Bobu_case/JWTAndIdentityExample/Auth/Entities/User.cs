namespace JWTAndIdentityExample.Auth.Entities
{
    public class User
    {
        public string Id { get; set; }
        public string? Name { get; set; }
        public string? Email { get; set; }
        public List<Parent>? Parents { get; set; }
    }
}
