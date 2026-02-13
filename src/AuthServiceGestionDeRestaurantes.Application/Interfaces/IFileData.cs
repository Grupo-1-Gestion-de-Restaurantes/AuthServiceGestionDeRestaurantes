namespace AuthServiceGestionDeRestaurantes.Application.Interfaces;

public interface IFileData
{
    byte [] Data { get;}
    string ContentType { get; }
    string FileName { get;}
    long Size {get;}
}