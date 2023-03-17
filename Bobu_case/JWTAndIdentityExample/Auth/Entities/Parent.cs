namespace JWTAndIdentityExample.Auth.Entities
{
    public class Parent
    {
        public string Id { get; set; }
        public string? Name { get; set; }
        public string? Email { get; set; }
        public List<User>? Users { get; set; }
    }
}
