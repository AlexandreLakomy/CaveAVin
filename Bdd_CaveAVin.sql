CREATE TABLE Utilisateur (
    ID_Utilisateur SERIAL PRIMARY KEY,
    Nom VARCHAR(255) NOT NULL,
    Prenom VARCHAR(255) NOT NULL,
    Email VARCHAR(255) UNIQUE NOT NULL,
    Telephone VARCHAR(255) NOT NULL,
    Login VARCHAR(255) UNIQUE NOT NULL,
    MotDePasse VARCHAR(255) NOT NULL
);

CREATE TABLE Cave (
    ID_Cave SERIAL PRIMARY KEY,
    Nom_Cave VARCHAR(255),
    Proprietaire_ID INTEGER REFERENCES Utilisateur(ID_Utilisateur)
);

CREATE TABLE Etagere (
    ID_Etagere SERIAL PRIMARY KEY,
    Numero VARCHAR(50),
    Region VARCHAR(255),
    Nb_place INTEGER,
    Cave_ID INTEGER REFERENCES Cave(ID_Cave)
);

CREATE TABLE TemplateBouteille (
    ID_Template SERIAL PRIMARY KEY,
    Domaine VARCHAR(255),
    Nom VARCHAR(255),
    Type_bouteille VARCHAR(50),
    Annee INTEGER,
    Region VARCHAR(255),
    Note_Moyenne FLOAT,
    Photo VARCHAR(255),
    Prix FLOAT
);

CREATE TABLE Bouteille (
    ID_Bouteille SERIAL PRIMARY KEY,
    Note_perso FLOAT,
    Etagere_ID INTEGER REFERENCES Etagere(ID_Etagere),
    Template_ID INTEGER REFERENCES TemplateBouteille(ID_Template)
    Nb_bouteille INTEGER,
    Archivee BOOLEAN DEFAULT FALSE;
    Commentaire TEXT;
);