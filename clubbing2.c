/* SP3CiFiC4Ti0NZ ******************************************************

  l4z3rz                   lyricz
    v                         v
~=-'-'-='~~-==---'I'll fly withhhh youuuuu~~~-==---==----~~=-'-'-='=='-~
                     DJ               d4nc3 lik3 h3ll       |
           (o_         \ qOp  _          v                  o/ ^
  o/  \o/   |   _o>  ____<|>__=_   o/  \o/ (o_  \o_   o_   <(  | up&d0wn
 <|    |   < \   |  |           | <|    |   |    |   <|     <\ v
 / >  < >       / \ |           | / >  < > < \  / >  < >    |
========================================================================
   l4z3rz
    v
~=-'-'-='~~-==--'-=,-=--,--'-~'=-~-'-=,-=--~~-==---==----~~=-'-'-='=='-~
  \o                                                | W.C. |   pr0n
_v_|>__\~/___v___   \o/     <o/ < d4nce lik3 h3ll   |      | o_  v
   ^             |   |       |                      |      | |,o_
   b4rm4id       |  / \     < \                     |      | \\<<
=anti&dek\==============================================================

***********************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sysexits.h>


#define DELTA 100000
#define MIN_SLEEP 300000
#define BUFSIZE 1024

void
draw_lasers(int line_nb, int rnd, char *buf, char *str) {
    /* 0: ~=-'-'-='~~-==---'I'll fly withhhh youuuuu~~~-==--- etc.
     * 1: none
     * ...
     * 5: none
     */
    int i, written, start_at, end_at = -1;
    char chr;
    char *laser = ",-~='";
    char *laser_color[] = {"\033[31m", "\033[32m", "\033[33m", "\033[34m",
        "\033[35m", "\033[36m", "\033[37m"};
    char *laser_attribute[] = {"\033[1m", "\033[5m", "\033[0m"};

    switch (line_nb) {
        case 0:
            if (str) {
                start_at = rand() % (72 + 1 - strlen(str));
                end_at = start_at + strlen(str) - 1;
            }
            written = 0;
            for (i = 0; i < 72; i++) {
                chr = i <= end_at && i >= start_at ? \
                    str[i - start_at] : laser[rand() % strlen(laser)];
                written += snprintf(buf + written, BUFSIZE, "%s%s%c",
                    laser_attribute[rand() % (sizeof(laser_attribute) / sizeof(char *))],
                    laser_color[rand() % (sizeof(laser_color) / sizeof(char *))],
                    chr);
            }
            snprintf(buf + written, BUFSIZE, "\033[0m");
            break;
        default:
            buf[0] = '\0';
    }
}

void
draw_ppl(int line_nb, int rnd, char *buf) {
    /* 0: none
     * 1:
     * 2:
     * 3: _o_
     * 4:  |
     * 5: /'\
     */
    char *people_body[][2] = {{" _\\o ", "  |  "}, {" o/_ ", "  |  "},
        {" _o_ ", "  |  "}, {" \\o_ ", "  |  "}, {" _o/ ", "  |  "},
        {" \\o/ ", "  |  "}, {" <o> ", "  |  "}, {" <o_ ", "  |  "},
        {" _o> ", "  |  "}, {" <o  ", "  |> "}, {"  o> ", " <|  "},
        {"  o  ", " <|> "}, {" _o  ", "  |> "}, {"  o_ ", " <|  "},
        {"  o/ ", " <|  "}, {" \\o  ", "  |> "}, {" \\\\o ", "  |  "},
        {" o// ", "  |  "}, {" o/> ", "  |  "}, {" <\\o ", "  |  "}};
    char *people_legs[] = {" <'> ", " <`\\ ", " /'> ", " /|  ", " /'\\ ",
        " |'| ", " <'| ", " |`> ", " /'| ", " |`\\ "};
    int which_sprite;

    if (rnd % 15 == 0) {
        /* JUMP! */
        line_nb++;
    }

    switch (line_nb) {
        case 0:
            buf[0] = '\0';
        case 1:
        case 2:
            (void)snprintf(buf, BUFSIZE, "     ");
            break;
        case 3:
        case 4:
            which_sprite = rnd % (sizeof(people_body) / (sizeof(char *) * 2));
            (void)snprintf(buf, BUFSIZE, "%s", people_body[which_sprite][line_nb - 3]);
            break;
        case 5:
            which_sprite = rand() % (sizeof(people_legs) / sizeof(char *));
            (void)snprintf(buf, BUFSIZE, "%s", people_legs[which_sprite]);
            break;
        default:
            (void)snprintf(buf, BUFSIZE, "     ");
    }
}

void
draw_dj(int line_nb, int rnd, char *buf) {
    /* 0: none
     * 1:
     * 2:      qOp  _ 
     * 3:  ____<|>__=_ 
     * 4: |           |
     * 5: |           | 
     */
    int which_sprite;
    char *dj_heads[] = {"qOp", "qO ", " Op"};
    char *dj_hands[] = {"<|>", "/|>", "/|\\", "<|\\"};

    switch (line_nb) {
        case 1:
            (void)snprintf(buf, BUFSIZE, "             ");
            break;
        case 2:
            which_sprite = rnd % (sizeof(dj_heads) / sizeof(char *));
            (void)snprintf(buf, BUFSIZE, "     %s  _  ", dj_heads[which_sprite]);
            break;
        case 3:
            which_sprite = rnd % (sizeof(dj_hands) / sizeof(char *));
            (void)snprintf(buf, BUFSIZE, " ____%s__=_ ", dj_hands[which_sprite]);
            break;
        case 4:
        case 5:
            (void)snprintf(buf, BUFSIZE, "|           |");
            break;
        default:
            buf[0] = '\0';
    }
}

void
draw_pole(int line_nb, int rnd, char *buf) {
    /* 0: none
     * 1:  |
     * 2:  \o_
     * 3:  /
     * 4: /|> 
     * 5:  |
     */
    char *pole_dancer[][3] = {{" _o/ ", "  \\  ", " <|\\ "},
        {"  \\o_", "  /  ", " /|> "}, {" o|  ", " <(  ", " <|\\ "},
        {"  |o ", "  )> ", " /|> "}, {"  |o/", "  (  ", " <|\\ "},
        {"\\o|  ", "  )  ", " /|> "}, {" \\o> ", "  )  ", " /|> "},
        {" _\\o ", "  /  ", " <|  "}, {" o/_ ", "  \\  ", "  |> "}};
    int which_sprite;

    if (line_nb == 0)
        buf[0] = '\0';
    else
        (void)snprintf(buf, BUFSIZE, "  |  ");

    line_nb -= rnd % 3;
    switch (line_nb) {
        case 1:
        case 2:
        case 3:
            which_sprite = rnd % (sizeof(pole_dancer) / (sizeof(char *) * 3));
            (void)snprintf(buf, BUFSIZE, "%s", pole_dancer[which_sprite][line_nb - 1]);
            break;
    }
}

void
draw_firstfloor() {
    #define POLE_PPL 2
    #define PARTY_PPL_FIRST 4
    #define PARTY_PPL_SECOND 3
    #define PARTY_PPL_THIRD 3
    #define PARTY_PPL PARTY_PPL_FIRST + PARTY_PPL_SECOND + PARTY_PPL_THIRD
    int people_rand[PARTY_PPL], pole_rand[POLE_PPL];
    char line[BUFSIZE], buf[BUFSIZE];
    int i, j, line_nb, rnd, which_lyrics;
    char *lyrics[] = {"HI! What's Your Name ?", "Want To be High ?!",
        "REACH FOR THE LASERS !!!", "SAFE AS FUCK!!!!",
        "I'll fly with youuuuu", "Rotterdam? Hooligan!",
        "I will live the world... Like children!!"};

    for (i = 0; i < PARTY_PPL; i++)
        people_rand[i] = rand();
    for (i = 0; i < POLE_PPL; i++)
        pole_rand[i] = rand();

    rnd = rand();
    for (i = 0; i < 6; i++) {
        line[0] = '\0';
        which_lyrics = rand() % (sizeof(lyrics) / sizeof(char *));
        (void)draw_lasers(i, 0, buf, lyrics[which_lyrics]);
        (void)strcat(line, buf);
        for (j = 0; j < PARTY_PPL_FIRST; j++) {
            (void)draw_ppl(i, people_rand[j], buf);
            (void)strcat(line, buf);
        }
        (void)draw_dj(i, rand(), buf);
        (void)strcat(line, buf);
        for (j = PARTY_PPL_FIRST; j < PARTY_PPL_FIRST + PARTY_PPL_SECOND; j++) {
            (void)draw_ppl(i, people_rand[j], buf);
            (void)strcat(line, buf);
        }
        (void)draw_pole(i, pole_rand[0], buf);
        (void)strcat(line, buf);
        for (j = PARTY_PPL_FIRST + PARTY_PPL_SECOND; j < PARTY_PPL; j++) {
            (void)draw_ppl(i, people_rand[j], buf);
            (void)strcat(line, buf);
        }
        (void)draw_pole(i, pole_rand[1], buf);
        (void)strcat(line, buf);
        (void)printf("%s\n", line);
    }
    printf("========================================================================\n");
}

void
draw_barmaid(int line_nb, int rnd, char *buf) {
    /* 0: none
     * 1: 
     * 2:   \o              
     * 3: _v_|>__\~/___v___ 
     * 4:                  |
     * 5:                  |
     */
    #define BAR_LENGTH 18
    int i, which_sprite, where_sprite;
    char *barmaid_body[][2] = {{"\\o_", "_|_"}, {"_o/", "_|_"},
        {" o ", "<|>"}, {"_o ", "_|>"}, {" o_", "<|_"},
        {"o/>", "_|_"}, {"<\\o", "_|_"}};
    char *glasses[] = {"v", "\\~/"};

    where_sprite = rnd % (BAR_LENGTH - 3);
    (void)memset(buf, ' ', BAR_LENGTH);
    buf[BAR_LENGTH] = '\0';
    switch (line_nb) {
        case 0:
            buf[0] = '\0';
            break;
        case 2:
            which_sprite = rnd % (sizeof(barmaid_body) / (sizeof(char *) * 2));
            (void)memcpy(buf + where_sprite,
                barmaid_body[which_sprite][0], 3);
            break;
        case 3:
            (void)memset(buf, '_', BAR_LENGTH - 1);
            for (i = 0; i < rand() % 4; i++) {
                which_sprite = rnd % (sizeof(glasses) / (sizeof(char *)));
                (void)memcpy(buf + rand() % (BAR_LENGTH - 2),
                    glasses[which_sprite], strlen(glasses[which_sprite]));
            }
            which_sprite = rnd % (sizeof(barmaid_body) / (sizeof(char *) * 2));
            (void)memcpy(buf + where_sprite,
                barmaid_body[which_sprite][1], 3);
            break;
        case 4:
        case 5:
            (void)snprintf(buf, BUFSIZE, "                 |");
            break;
    }
}

void
draw_secondfloor() {
    #define PARTY_PPL_BIS 7
    int people_rand[PARTY_PPL_BIS];
    char line[BUFSIZE], buf[BUFSIZE];
    int i, j, line_nb, rnd;

    for (i = 0; i < PARTY_PPL_BIS; i++)
        people_rand[i] = rand();

    rnd = rand();
    for (i = 0; i < 6; i++) {
        line[0] = '\0';
        (void)draw_lasers(i, 0, buf, NULL);
        (void)strcat(line, buf);
        (void)draw_barmaid(i, rnd, buf);
        (void)strcat(line, buf);
        for (j = 0; j < PARTY_PPL_BIS; j++) {
            (void)draw_ppl(i, people_rand[j], buf);
            (void)strcat(line, buf);
        }
        (void)printf("%s\n", line);
    }
    printf("=anti&dek\\==============================================================\n");
}

int
main(int argc, char **argv) {
    while (1) {
        (void)draw_firstfloor();
        (void)draw_secondfloor();
        (void)printf("\033[14A");
        (void)usleep(MIN_SLEEP + rand() % DELTA);
    }
}
